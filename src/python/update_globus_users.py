#!/usr/bin/env python
#
##################################################################################
#
#     Title : update_globus_users.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 04/28/2015
#   Purpose : Python script to update Globus user information.
#
# Work File : $DSSHOME/bin/update_globus_users.py*
# Test File : $DSSHOME/bin/update_globus_users_test.py*
#  SVN File : $HeadURL: https://subversion.ucar.edu/svndss/tcram/python/update_globus_users.py $
#
##################################################################################

import sys
path1 = "/glade/u/home/rdadata/lib/python"
path2 = "/glade/u/home/tcram/lib/python"
if (path1 not in sys.path):
	sys.path.append(path1)
if (path2 not in sys.path):
	sys.path.append(path2)

from MyGlobus import MyGlobus
from PyDBI import myget, myadd, myupdt
from globus_utils import load_app_client
import logging
import logging.handlers
from globus_sdk import (TransferClient, TransferAPIError, RefreshTokenAuthorizer,
                        GlobusError, GlobusAPIError, NetworkError)

#=========================================================================================
def main(args):
	my_logger.info('Getting ACL list')
	acls = get_acls(args['endpoint_id'])
	
	# Resource document data key/value pairs to retain
	task_keys = ['id','path','principal','principal_type']

	if doprint: print_doc(acls, task_keys)

	# Prepare database records and insert records
	if (len(acls) == 0):
		msg = "[main] There is no data in the return document."
		print (msg)
		my_logger.warning(msg)
	else:
		records = create_recs(acls, task_keys)
		update_users(records)
		
#=========================================================================================
def get_acls(endpoint_id):
	""" Get list of access rules in the ACL for a specified endpoint """
	try:
		acls = []
		tc_authorizer = RefreshTokenAuthorizer(MyGlobus['transfer_refresh_token'], load_app_client())
		tc = TransferClient(authorizer=tc_authorizer)
		for rule in tc.endpoint_manager_acl_list(endpoint_id, num_results=None):
			acls.append(rule)
	except GlobusAPIError as e:
		msg = ("[get_acls] Globus API Error\n"
		       "HTTP status: {}\n"
		       "Error code: {}\n"
		       "Error message: {}").format(e.http_status, e.code, e.message)
		my_logger.error(msg)
		raise e
	except NetworkError:
		my_logger.error(("[get_acls] Network Failure. "
                   "Possibly a firewall or connectivity issue"))
		raise
	except GlobusError:
		logging.exception("[get_acls] Totally unexpected GlobusError!")
		raise

	return acls
	
#=========================================================================================
def update_users(data):
	""" Insert/update user records in gouser and goshare """

	from datetime import date
	datestamp = date.today().isoformat()
	rec = {}
	for i in range(len(data)):
		if (data[i]['principal_type'] == 'identity'):
			id = data[i]['id']
			principal = data[i]['principal']
			condition = " WHERE {0}='{1}'".format("globus_rid", id)
			myrec = myget('goshare', ['email','username'], condition)
			
			if (len(myrec) > 0 and myrec['email'] != None):
				email = myrec['email']
				rec['username'] = principal

				# Insert/Update gouser record
				user_cond = " WHERE {0}='{1}' AND {2} {3}".format("email",email,"end_date",'IS NULL')
				myruser = myget('ruser', ['id'], user_cond)
				if (len(myruser) > 0):
					gorec = {'email'        : email,
					         'id'           : myruser['id'],
					         'username'     : principal,
					         'creation_date': datestamp, \
					         'status'       : 'ACTIVE'}

					# Check if record already exists in gouser table
					gocond = " WHERE email='{0}' AND id={1} AND username='{2}'".format(email,myruser['id'],principal)
					mygouser = myget('gouser', ['*'], gocond)
					
					# Add if no record
					if (len(mygouser) == 0):
						myadd('gouser', gorec)					
					elif (mygouser['status'] == 'INACTIVE'):
						my_logger.info("Updating Globus user record ({0}) to 'ACTIVE'".format(mygouser['username']))
						myupdt('gouser', {'status': 'ACTIVE'}, gocond)						
					else:
						my_logger.info('[main] Globus user name {0} is up to date in the gouser table'.format(mygouser['username']))

			# Update Globus user name in goshare record
				if (myrec['username'] == None or not (myrec['username'] == principal)):
					myupdt('goshare', rec, condition)
				else:
					my_logger.info('[main] Globus user name {0} is up to date in the goshare table.'.format(myrec['username']))

	return
	
#=========================================================================================
# Parse the command line arguments

def parse_opts(argv):
	import getopt
	from datetime import timedelta
	global doprint

	usg = 'Usage: update_globus_users.py -n ENDPOINT'	

	# Default arguments
	endpoint = 'rda#data_request'
	doprint = bool(False)
	rem = ''
	
	print ('ARGV      :',argv)
	opts, rem = getopt.getopt(argv, 'n:p', ['endpoint=','print'])
	
	print ('OPTIONS   :',opts)
	
	for opt, arg in opts:
		if opt in ('-n', '--endpoint'):
			endpoint = arg
		elif opt in ('-p', '--print'):
			doprint = bool(True)
		elif opt in ('-h', '--help'):
			print (usg)
	
	if (endpoint == 'rda#data_request'):
		endpoint_id = MyGlobus['data_request_ep']
	elif (endpoint == 'rda#datashare'):
		endpoint_id = MyGlobus['datashare_ep']
	else:
		msg = "[parse_opts] Globus endpoint {0} not found.".format(endpoint)
		print (msg)
		my_logger.warning(msg)
		sys.exit()

	print ('ENDPOINT   : {}'.format(endpoint))
	print ('ENDPOINT ID: {}'.format(endpoint_id))
	print ('PRINT      : {}'.format(doprint))
	print ('REMAINING  : {}'.format(rem))

	return {'endpoint': endpoint, \
	        'endpoint_id': endpoint_id, \
            'rem': rem}

#=========================================================================================
# Create a list of dictionaries (records) from the 'DATA' task document output, to be 
# inserted into the database.

def create_recs(data, keys):
	records = []
	go_dict = {}
	for i in range(len(data)):
		for key in data[i].keys():
			if key in keys:
				go_dict[key] = data[i][key]
			else:
				continue
		records.append(go_dict)
		go_dict = {}
	return records
	
#=========================================================================================
# Print output from the response object

def print_doc(data, keys):
	for i in range(len(data)):
		print ()
		for key in data[i].keys():
			if key in keys:
				print (key, '\t', data[i][key])
			else:
				continue

#=========================================================================================
# Configure log file

def configure_log(**kwargs):
	""" Set up log file """
	LOGPATH = '/glade/scratch/tcram/logs/globus/'
	LOGFILE = 'update_globus_users.log'

	if 'level' in kwargs:
		loglevel = kwargs['level']
	else:
		loglevel = 'info'

	LEVELS = { 'debug':logging.DEBUG,
               'info':logging.INFO,
               'warning':logging.WARNING,
               'error':logging.ERROR,
               'critical':logging.CRITICAL,
             }

	level = LEVELS.get(loglevel, logging.INFO)
	my_logger.setLevel(level)
	handler = logging.handlers.RotatingFileHandler(LOGPATH+'/'+LOGFILE,maxBytes=200000,backupCount=1)
	handler.setLevel(level)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	my_logger.addHandler(handler)
	
	return

#=========================================================================================
""" Set up logging """
my_logger = logging.getLogger(__name__)
configure_log(level='info')

if __name__ == "__main__":
	args = parse_opts(sys.argv[1:])
	main(args)
