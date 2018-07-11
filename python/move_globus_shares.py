#!/usr/bin/env python
#
##################################################################################
#
#     Title : move_globus_shares.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 04/02/2018
#   Purpose : Python script to move all current Globus shares to the new
#             RDA shared endpoints on /glade2/collections/rda.  Current shares on
#             the old endpoints with host path /glade/p/rda will be deleted.
#
#   Modified 11 Jul 2018: New shared endpoints created to accommodate glade migration
#                         from /glade2/collections/rda to /glade/collections/rda
#                         (T. Cram)
#
# Work File : $DSSHOME/bin/move_globus_shares.py*
# Test File : $DSSHOME/bin/move_globus_shares_test.py*
#
##################################################################################

import sys
path1 = "/glade/u/home/rdadata/lib/python"
path2 = "/glade/u/home/tcram/lib/python"
if (path1 not in sys.path):
	sys.path.append(path1)
if (path2 not in sys.path):
	sys.path.append(path2)

from MyGlobus import MyGlobus, DSS_DATA_PATH
from PyDBI import myget, myupdt, mymget
import logging
import logging.handlers
from globus_sdk import (TransferClient, TransferAPIError, AccessTokenAuthorizer,
                        GlobusError, GlobusAPIError, NetworkError)

from dsglobus import get_user_id
try:
    from urllib.parse import urlencode
except:
    from urllib import urlencode
  
#=========================================================================================
def main(args):
	my_logger.info('Getting ACL list')

	db_acls = get_db_acls()
	acls = get_acls(args['endpoint_id_legacy'])
	create_new_acls(db_acls, args['action'])
	
#=========================================================================================
def get_db_acls():

	cond = " WHERE source_endpoint='rda#data_request' AND status='ACTIVE' and delete_date IS NULL"
	db_acls = mymget('goshare', ['email','dsid','globus_rid', 'acl_path', 'rindex'], cond)

	"""	
	cond = " WHERE source_endpoint='rda#datashare' AND status='ACTIVE' and delete_date IS NULL"
	db_acls = mymget('goshare', ['email','dsid','globus_rid', 'acl_path'], cond)
	"""
	
	return db_acls

#=========================================================================================
def get_acls(endpoint_id):
	""" Get list of access rules in the ACL for a specified endpoint """
	try:
		acls = []
		tc = TransferClient(authorizer=AccessTokenAuthorizer(MyGlobus['transfer_token']))
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
def create_new_acls(acl_list, action):
	""" Query Globus share record.  Create ACL on new shared endpoint if record exists 
	    and is marked as ACTIVE. """

	for i in range(len(acl_list)):
		acl_id = acl_list[i]['globus_rid']
		dsid = acl_list[i]['dsid']
		email = acl_list[i]['email']
		path = acl_list[i]['acl_path']
		if (action == 1):
			ridx = acl_list[i]['rindex']
		if (acl_id):
			data = {"dsid": dsid,
	                "email": email,
	                "acl_path": path,
	                "old_rule_id": acl_id}
			if (action == 1):
				data.update({'ridx': acl_list[i]['rindex']})
	                
			add_endpoint_acl_rule_new(action, data)
			
	return

#=========================================================================================
def add_endpoint_acl_rule_new(action, data):
	""" Create a new endpoint access rule
	    action = 1: dsrqst share
	           = 2: standard dataset share
	"""
	if (action == 1):
		try:
			endpoint_id = MyGlobus['data_request_ep']
			ridx = data['ridx']
			cond = " WHERE rindex='{0}'".format(ridx)
			myrqst = myget('dsrqst', ['*'], cond)
			if (len(myrqst) == 0):
				msg = "[add_endpoint_acl_rule] Request index not on file"
				my_logger.warning(msg)
				if 'print' in data and data['print']:
					sys.exit("Error: {0}".format(msg))
				return {'Error': msg}
			rqstid = myrqst['rqstid']
			email = myrqst['email']
			dsid = myrqst['dsid']
			share_data = {'ridx': ridx, 'dsid': dsid, 'email': email}
			path = construct_share_path(1, share_data)
		except KeyError as err:
			return handle_error(err, name="[add_endpoint_acl_rule]", print_stdout=print_stdout)

	elif (action == 2):
		try:
			endpoint_id = MyGlobus['datashare_ep']
			dsid = data['dsid']
			email = data['email']
			"""
			cond = " WHERE email='{0}' AND dsid='{1}' AND status='ACTIVE'".format(email, dsid)
			myshare = myget('goshare', ['*'], cond)
			if (len(myshare) > 0 and myshare['globus_rid']):
				msg = "[add_endpoint_acl_rule] Globus ACL rule has already been created for user {0} and dataset {1}. ACL rule {2}".format(email, dsid, myshare['globus_rid'])
				my_logger.info(msg)
				if 'print' in data and data['print']:
					sys.exit(msg)
				return {'access_id': myshare['globus_rid'], 'share_url': myshare['globus_url']}
			"""
			share_data = {'dsid': dsid}
			path = construct_share_path(2, share_data)
			path = data['acl_path']
			share_data.update({'email': email})
		except KeyError as err:
			return handle_error(err, name="[add_endpoint_acl_rule]", print_stdout=print_stdout)

	rda_identity = "{0}@rda.ucar.edu".format(email)
	identity_id = get_user_id(rda_identity)
	share_data.update({'identity': identity_id})
	rule_data = {
	    "DATA_TYPE": "access",
	    "principal_type": "identity",
	    "principal": identity_id,
	    "path": path,
	    "permissions": "r"
 	}
 	if 'notify' in data:
 		rule_data.update({"notify_email": email})	

	try:
		tc = TransferClient(authorizer=AccessTokenAuthorizer(MyGlobus['transfer_token']))
		result = tc.add_endpoint_acl_rule(endpoint_id, rule_data)
	except GlobusAPIError as e:
		msg = ("[add_endpoint_acl_rule] Globus API Error\n"
		       "HTTP status: {}\n"
		       "Error code: {}\n"
		       "Error message: {}").format(e.http_status, e.code, e.message)
		my_logger.error(msg)
		# raise e
		if (e.http_status == 409 and e.code == 'Exists'):
			return
	except NetworkError:
		my_logger.error(("[add_endpoint_acl_rule] Network Failure. "
                   "Possibly a firewall or connectivity issue"))
		raise
	except GlobusError:
		logging.exception("[add_endpoint_acl_rule] Totally unexpected GlobusError!")
		raise
	
	msg = "{0}\nResource: {1}\nRequest ID: {2}\nAccess ID: {3}".format(result['message'], result['resource'], result['request_id'], result['access_id'])
	if 'print' in data and data['print']:
		print msg
	my_logger.info("[add_endpoint_acl_rule] {0}".format(msg))
	my_logger.info("[add_endpoint_acl_rule] User email: {0}".format(email))
	
	if 'print' in data and data['print']:
		share_data.update({'print': True})
	
	url = construct_share_url(action, share_data)
	share_data.update({'globus_rid': result['access_id'],
	                   'globus_url': url,
	                   'old_rule_id': data['old_rule_id']})
	update_share_record(action, share_data)
	
	return {'access_id': result["access_id"], 'share_url': url}

	
#=========================================================================================
def construct_share_path(action, data):
	""" Construct the path to the shared data.  Path is relative to the 
	    shared endpoint base path.
	    
	    action = 1: dsrqst share
	           = 2: standard dataset share
	"""
	if 'print' in data:
		print_stdout = data['print']
	else:
		print_stdout = False

	if (action == 1):
		try:
			ridx = data['ridx']
			cond = " WHERE rindex='{0}'".format(ridx)
			myrqst = myget('dsrqst', ['rqstid','location'], cond)
			if (len(myrqst) > 0):
				if myrqst['location']:
					base_path = "{0}/transfer/".format(MyGlobus['DSS_DATA_PATH'])
					loc = myrqst['location']
					if (loc.find(base_path) != -1):
						path_len = len(base_path)
						path = "/{0}/".format(loc[path_len:])
					else:
						path = None
				else:
					path = "/dsrqst/{0}/".format(myrqst['rqstid'])
			else:
				msg = "[construct_share_path] Request index {0} not found or request ID not defined".format(ridx)
				if 'print' in data and data['print']:
					sys.exit("Error: {0}".format(msg))
				my_logger.error(msg)
				return {'Error': msg}
		except KeyError as err:
			return handle_error(err, name="[construct_share_path]", print_stdout=print_stdout)
	elif (action == 2):
		try:
			path = "/{0}/".format(data['dsid'])
		except KeyError as err:
			return handle_error(err, name="[construct_share_path]", print_stdout=print_stdout)

	my_logger.info("[construct_share_path] Path to shared data: {0}".format(path))
	return path

#=========================================================================================
def construct_share_url(action, data):
	""" Construct the URL to the shared data on the Globus web app 
	
		action = 1: dsrqst shares
		       = 2: standard dataset share
	"""
	if 'print' in data:
		print_stdout = data['print']
	else:
		print_stdout = False

	if (action == 1):
		try:
			ridx = data['ridx']
			cond = ' WHERE rindex={0}'.format(ridx)
			myrqst = myget('dsrqst', ['*'], cond)
			if (len(myrqst) > 0):
				origin_id = MyGlobus['data_request_ep']
				origin_path = construct_share_path(1, {'ridx': ridx})
			else:
				msg = "[construct_share_url] Request {0} not found in RDADB".format(ridx)
				if 'print' in data and data['print']:
					sys.exit("Error: {0}".format(msg))
				my_logger.warning(msg)
				return {'Error': msg}
		except KeyError as err:
			return handle_error(err, name="[construct_share_url]", print_stdout=print_stdout)

	if (action == 2):
		try:
			origin_id = MyGlobus['datashare_ep']
			origin_path = construct_share_path(2, {'dsid': data['dsid']})
		except KeyError as err:
			return handle_error(err, name="[construct_share_url]", print_stdout=print_stdout)

	params = {'origin_id': origin_id, 'origin_path': origin_path}
	if 'identity' in data:
		params.update({'add_identity': data['identity']})
	
	url = '{0}transfer?{1}'.format(MyGlobus['globusURL'], urlencode(params))
	
	my_logger.info("[construct_share_url] Globus share URL created: {0}".format(url))
	return url

#=========================================================================================
def update_share_record(action, data):
	""" Update the user's Globus share in RDADB
	    action = 1: dsrqst share
	           = 2: standard dataset share
	"""
	if ('print' in data):
		print_stdout = data['print']
	else:
		print_stdout = False
	
	try:
		globus_rid = data['globus_rid']
		globus_url = data['globus_url']
		old_rule_id = data['old_rule_id']
	except KeyError as err:
		return handle_error(err, name="[update_share_record]", print_stdout=print_stdout)
	
	share_record = {'globus_rid': '{0}'.format(globus_rid),
                    'globus_url': '{0}'.format(globus_url)}
	cond = " WHERE globus_rid='{0}'".format(old_rule_id)
	
	if (action == 1):
		try:
			ridx = data['ridx']
			myupdt('dsrqst', share_record, cond)
			my_logger.info("[update_share_record] dsrqst record updated. Request index: {0}.  ACL rule ID: {1}.".format(ridx, globus_rid))
			myupdt('goshare', share_record, cond)
			my_logger.info("[update_share_record] Share record updated. Old rule ID: {0}, new ACL rule ID: {1}.".format(old_rule_id, globus_rid)) 
		except KeyError as err:
			return handle_error(err, name="[update_share_record]", print_stdout=print_stdout) 
	elif (action == 2):
		try:
			myupdt('goshare', share_record, cond)
			my_logger.info("[update_share_record] Share record updated. Old rule ID: {0}, new ACL rule ID: {1}.".format(old_rule_id, globus_rid)) 
		except KeyError as err:
			return handle_error(err, name="[update_share_record]", print_stdout=print_stdout)

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
	
	print 'ARGV      :',argv
	opts, rem = getopt.getopt(argv, 'n:p', ['endpoint=','print'])
	
	print 'OPTIONS   :',opts
	
	for opt, arg in opts:
		if opt in ('-n', '--endpoint'):
			endpoint = arg
		elif opt in ('-p', '--print'):
			doprint = bool(True)
		elif opt in ('-h', '--help'):
			print usg
	
	if (endpoint == 'rda#data_request'):
		endpoint_id = MyGlobus['data_request_ep_legacy2']
		action = 1
	elif (endpoint == 'rda#datashare'):
		endpoint_id = MyGlobus['datashare_ep_legacy2']
		action = 2
	else:
		msg = "[parse_opts] Globus endpoint {0} not found.".format(endpoint)
		print msg
		my_logger.warning(msg)
		sys.exit()

	print 'ENDPOINT          : {}'.format(endpoint)
	print 'LEGACY ENDPOINT ID: {}'.format(endpoint_id)
	print 'PRINT             : {}'.format(doprint)
	print 'REMAINING         : {}'.format(rem)

	return {'endpoint': endpoint, \
	        'endpoint_id_legacy': endpoint_id, \
	        'action': action, \
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
		print '\n'
		for key in data[i].keys():
			if key in keys:
				print key, '\t', data[i][key]
			else:
				continue

#=========================================================================================
# Configure log file

def configure_log(**kwargs):
	""" Set up log file """
	LOGPATH = '/glade/scratch/tcram/logs/globus/'
	LOGFILE = 'move_globus_shares.log'

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
