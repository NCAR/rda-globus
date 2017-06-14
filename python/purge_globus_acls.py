#!/usr/bin/env python
#
##################################################################################
#
#     Title : purge_globus_acls.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 06/07/2017
#   Purpose : Python script to delete old ACLs on RDA Globus endpoints.
#
# Work File : $DSSHOME/bin/purge_globus_acls.py*
# Test File : $DSSHOME/bin/purge_globus_acls_test.py*
#
##################################################################################

import os, sys

sys.path.append("/glade/u/home/rdadata/lib/python")
sys.path.append("/glade/u/home/tcram/lib/python")
sys.path.append("/glade/u/apps/contrib/globus-sdk/1.1.0")

import logging
import logging.handlers
import re

from MyGlobus import headers, MyGlobus
from PyDBI import myget, mymget, myadd, myupdt
from globus_sdk import (TransferClient, TransferAPIError, AccessTokenAuthorizer,
                        GlobusError, GlobusAPIError, NetworkError)

#=========================================================================================
def main():

	rqst_acls = get_acls(MyGlobus['data_request_ep'])
	if (len(rqst_acls) > 0):
		delete_rqst_acls(rqst_acls, MyGlobus['data_request_ep'])
	
#=========================================================================================
def get_acls(endpoint_id):

	acl_list = []

	try:
		tc = TransferClient(authorizer=AccessTokenAuthorizer(MyGlobus['transfer_token']))
		for acl in tc.endpoint_acl_list(endpoint_id):
			acl_list.append(acl)
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

	my_logger.info("[get_acls] {0} ACLs retrieved from endpoint {1}".format(len(acl_list), endpoint_id))
	return acl_list

#=========================================================================================
def delete_rqst_acls(acl_list, endpoint_id):
	
	tc = TransferClient(authorizer=AccessTokenAuthorizer(MyGlobus['transfer_token']))
	
	count = 0
	
	for i in range(len(acl_list)):
		path = acl_list[i]['path']
		acl_id = acl_list[i]['id']
		
		searchObj = re.search(r'/[a-zA-Z]+\d+/$', path)
		if searchObj:
			ridx = re.sub(r'\D', "", searchObj.group())
		
		# Query request record.  Delete ACL if record doesn't exist.
		condition = " WHERE {0}={1}".format('rindex', ridx)
		myrec = myget('dsrqst', ['globus_rid'], condition)
		if (len(myrec) == 0 and acl_id):
			try:
				result = tc.delete_endpoint_acl_rule(endpoint_id, acl_id)
				count += 1
			except GlobusAPIError as e:
				my_logger.error(("[delete_rqst_acls] Globus API Error\n"
		                 "HTTP status: {}\n"
		                 "Error code: {}\n"
		                 "Error message: {}").format(e.http_status, e.code, e.message))
				raise e
			except NetworkError:
				my_logger.error(("[delete_rqst_acls] Network Failure. "
                   "Possibly a firewall or connectivity issue"))
				raise
			except GlobusError:
				logging.exception("[delete_rqst_acls] Totally unexpected GlobusError!")
				raise
    
			msg = "{0}\nResource: {1}\nRequest ID: {2}".format(result['message'], result['resource'], result['request_id'])
			if 'print' in data and data['print']:
				print msg
			my_logger.info("[delete_rqst_acls] {0}".format(msg))

	my_logger.info("[delete_rqst_acls] {0} ACLs purged from endpoint rda#data_request ({1})".format(count, endpoint_id))

	return
	
#=========================================================================================
# Configure log file

def configure_log(**kwargs):
	""" Set up log file """
	LOGPATH = '/glade/p/rda/work/tcram/logs/globus'
	LOGFILE = 'purge_globus_acls.log'

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
	handler = logging.handlers.RotatingFileHandler(LOGPATH+'/'+LOGFILE,maxBytes=200000000,backupCount=3)
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
	main()
