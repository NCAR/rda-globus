#!/usr/bin/env python
#
##################################################################################
#
#     Title : delete_legacy_shares.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 08/31/2018
#   Purpose : Python script to delete Globus shares from legacy RDA shared
#             endpoints that are no longer used (e.g. NCAR RDA Dataset Archive
#             (legacy v2).
#
# Work File : $DSSHOME/bin/delete_legacy_shares.py*
# Test File : $DSSHOME/bin/delete_legacy_shares_test.py*
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

	endpoint_id_legacy = args['endpoint_id_legacy']

	tc = TransferClient(authorizer=AccessTokenAuthorizer(MyGlobus['transfer_token']))
	endpoint = tc.get_endpoint(endpoint_id_legacy)

	msg = "Endpoint: {0}".format(endpoint['display_name'])
	print msg
	my_logger.info("[main] {0}".format(msg))
	msg =  "Endpoint ID: {0}".format(endpoint['id'])
	print msg
	my_logger.info("[main] {0}".format(msg))

	if (endpoint_id_legacy == MyGlobus['datashare_ep'] or endpoint_id_legacy == MyGlobus['data_request_ep']):
		msg = "[main] Endpoint ID {0} is an active endpoint!".format(endpoint_id_legacy)
		my_logger.error(msg)
		sys.exit("Error: {0}".format(msg))
	
	acls = get_acls(endpoint_id_legacy)
	
	msg = "Number of ACLs on endpoint {0}: {1}".format(endpoint['display_name'], len(acls))
	print msg
	my_logger.info("[main] {0}".format(msg))
	
	count = delete_acls(endpoint_id_legacy, acls)

	msg = "{0} legacy ACLs deleted successfully from endpoint {1}".format(count, endpoint['display_name'])
	print msg
	my_logger.info("[main] {0}".format(msg))
	
	
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
def delete_acls(endpoint_id, acl_list):

	rda_identity = get_user_id('rda@globusid.org')
	count = 0
	
	for i in range(len(acl_list)):
		rule_id = acl_list[i]['id']
		
		""" Skip ACL assigned to RDA identity """
		if acls[i]['principal'] == rda_identity or not acls[i]['id']:
			continue
			
		try:
			tc = TransferClient(authorizer=AccessTokenAuthorizer(MyGlobus['transfer_token']))
			result = tc.delete_endpoint_acl_rule(endpoint_id, rule_id)
		except GlobusAPIError as e:
			my_logger.error(("[delete_endpoint_acl_rule] Globus API Error\n"
		    	             "HTTP status: {}\n"
		        	         "Error code: {}\n"
		            	     "Error message: {}").format(e.http_status, e.code, e.message))
			raise e
		except NetworkError:
			my_logger.error(("[delete_endpoint_acl_rule] Network Failure. "
            	       "Possibly a firewall or connectivity issue"))
			raise
		except GlobusError:
			logging.exception("[delete_endpoint_acl_rule] Totally unexpected GlobusError!")
			raise
    
		msg = "{0}\nResource: {1}\nRequest ID: {2}".format(result['message'], result['resource'], result['request_id'])
		print msg
		my_logger.info("[delete_endpoint_acl_rule] {0}".format(msg))
		
		if result['code'] == "Deleted":
			count = count + 1

	return count
		
#=========================================================================================
# Parse the command line arguments

def parse_opts(argv):
	import getopt
	from datetime import timedelta
	global doprint

	usg = 'Usage: delete_legacy_shares.py -n ENDPOINT'	

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
		endpoint_id_legacy = MyGlobus['data_request_ep_legacy']
	elif (endpoint == 'rda#datashare'):
		endpoint_id_legacy = MyGlobus['datashare_ep_legacy']
	else:
		msg = "[parse_opts] Globus endpoint {0} not found.".format(endpoint)
		print msg
		my_logger.warning(msg)
		sys.exit()

	print 'ENDPOINT          : {}'.format(endpoint)
	print 'LEGACY ENDPOINT ID: {}'.format(endpoint_id_legacy)
	print 'PRINT             : {}'.format(doprint)
	print 'REMAINING         : {}'.format(rem)

	return {'endpoint': endpoint, \
	        'endpoint_id_legacy': endpoint_id_legacy, \
            'rem': rem}

#=========================================================================================
# Configure log file

def configure_log(**kwargs):
	""" Set up log file """
	LOGPATH = '/glade/scratch/tcram/logs/globus/'
	LOGFILE = 'delete_legacy_shares.log'

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
