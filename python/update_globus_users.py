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

import requests
import os, sys

sys.path.append("/glade/u/home/rdadata/lib/python")
sys.path.append("/glade/u/home/tcram/lib/python")

from PyDBI import myget, myadd, myupdt
from datetime import date
import logging
import logging.handlers

url = 'https://transfer.api.globusonline.org/v0.10/'
token_file = open('/glade/u/home/rdadata/dssdb/tmp/.globus/globus.transfer-token', 'r')
gotoken = token_file.read().rstrip('\\n')
headers = {'Authorization':'Bearer '+gotoken}

#=========================================================================================
def main(args):
	datestamp = date.today().isoformat()
	my_logger.info('Getting ACL list')
	resource = 'endpoint/' + args['endpointID'] + '/access_list'
	r = requests.get(url+resource, headers=headers)
	data = r.json()

	# Resource document data key/value pairs to retain
	task_keys = ['id','path','principal','principal_type']

	if doprint: print_doc(data, task_keys)

	# Prepare database records
	if (len(data['DATA']) >= 1):
		records = create_recs(data, task_keys)
	else:
		my_logger.warning('[main] There is no data in the return document.')
		sys.exit()
		
	# Get user e-mail address for corresponding ACL rule ID and Globus user
	if (args['endpoint'] == 'rda%23datashare'):
		tablename = 'goshare'
		fieldlist = ['email','username']
	elif (args['endpoint'] == 'rda%23data_request'):
		tablename = 'dsrqst'
		fieldlist = ['email']
	
	rec = {}
	for i in range(len(records)):
		if (records[i]['principal_type'] == 'user'):
			id = records[i]['id']
			principal = records[i]['principal']
			condition = " WHERE {0}={1}".format("globus_rid", id)
			myrec = myget(tablename, fieldlist, condition)
			
			if (len(myrec) > 0 and myrec['email'] != None):
				email = myrec['email']
				rec['username'] = principal

				# Insert/Update gouser record
				user_cond = " WHERE {0}='{1}' AND {2} {3}".format("email",email,"end_date",'IS NULL')
				myruser = myget('ruser', ['id'], user_cond)
				if (len(myruser) > 0):
					gorec = {'email': email, 'id': myruser['id'], 'username': principal, 
					'creation_date': datestamp, 'status': 'ACTIVE'}

					# Check if record already exists in gouser table
					gocond = " WHERE {0}='{1}' AND {2}={3} AND {4}='{5}'".format("email",email,"id",myruser['id'],"username",principal)
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
				if (tablename == 'goshare'):
					if (myrec['username'] == None or cmp(myrec['username'],principal) != 0):
						myupdt(tablename, rec, condition)
					else:
						my_logger.info('[main] Globus user name {0} is up to date in the goshare table.'.format(myrec['username']))
	
#=========================================================================================
# Parse the command line arguments

def parse_opts(argv):
	import getopt
	from datetime import timedelta
	global doprint

	usg = 'Usage: update_globus_users.py -n ENDPOINT'	

	# Default arguments
	endpoint = 'rda%23data_request'
	doprint = bool(False)
	rem = ''
	
	print 'ARGV      :',argv
	opts, rem = getopt.getopt(argv, 'n:p', ['endpoint=','print'])
	
	print 'OPTIONS   :',opts
	
	for opt, arg in opts:
		if opt in ('-n', '--endpoint'):
			endpoint = arg.replace("#","%23")
		elif opt in ('-p', '--print'):
			doprint = bool(True)
		elif opt in ('-h', '--help'):
			print usg
	
	if (endpoint == 'rda%23data_request'):
		endpointID = 'd20e610e-6d04-11e5-ba46-22000b92c6ec'
	elif (endpoint == 'rda%23datashare'):
		endpointID = 'db57de42-6d04-11e5-ba46-22000b92c6ec'
	else:
		msg = 'Globus endpoint {0} not found.'.format(endpoint)
		print msg
		my_logger.warning(msg)
		sys.exit()

	print 'ENDPOINT   :', endpoint
	print 'ENDPOINT ID:', endpointID
	print 'PRINT      :', doprint
	print 'REMAINING  :', rem

	return {'endpoint': endpoint, \
	        'endpointID': endpointID, \
            'rem': rem}

#=========================================================================================
# Create a list of dictionaries (records) from the 'DATA' task document output, to be 
# inserted into the database.

def create_recs(data, keys):
	records = []
	go_dict = {}
	for i in range(len(data['DATA'])):
		for key in data['DATA'][i]:
			if key in keys:
				go_dict[key] = data['DATA'][i][key]
			else:
				continue
		records.append(go_dict)
		go_dict = {}
	return records
	
#=========================================================================================
# Print output from the 'DATA' task document

def print_doc(data, keys):
	for i in range(len(data['DATA'])):
		print '\n'
		for key in data['DATA'][i]:
			if key in keys:
				print key, '\t', data['DATA'][i][key]
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
