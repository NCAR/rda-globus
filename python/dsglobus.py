#!/usr/bin/env python
#
##################################################################################
#
#     Title : dsglobus.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 02/17/2017
#   Purpose : Python module to create and manage shared endpoints to facilitate
#             Globus data transfers from the RDA.
#
# Work File : $DSSHOME/bin/dsglobus.py*
# Test File : $DSSHOME/bin/dsglobus_test.py*
# Github    : https://github.com/NCAR/rda-globus/python/dsglobus.py
#
##################################################################################

import os, sys

sys.path.append("/glade/u/apps/contrib/modulefiles/globus-sdk")
sys.path.append("/glade/u/home/rdadata/lib/python")
sys.path.append("/glade/u/home/tcram/lib/python")

from MyGlobus import headers, MyGlobus
from PyDBI import myget, myupdt, myadd
from globus_sdk import (TransferClient, TransferAPIError, AccessTokenAuthorizer,
                        AuthClient)
from globus_utils import load_portal_client
import json
import logging
import logging.handlers

try:
    from urllib.parse import urlencode
except:
    from urllib import urlencode

def main():
	parse_input()

def add_endpoint_acl_rule(action, data):
	""" Create a new endpoint access rule """
	try:
		email = data['email']
		rda_identity = "{0}@rda.ucar.edu".format(email)
	except KeyError as err:
		my_logger.error("[add_endpoint_acl_rule] {0}".format(err), exc_info=True)
		sys.exit(1)
	
	if (action == 1):
		try:
			endpoint_id = MyGlobus['data_request_ep']
			ridx = data['ridx']
			cond = " WHERE rindex='{0}'".format(ridx)
			myrqst = myget('dsrst', ['*'], cond)
			if (len(myrqst) == 0):
				print "Request index not on file"
				sys.exit(1)
			rqstid = myrqst['rqstid']
			if myrqst['globus_rid']:
				my_logger.info("[add_endpoint_acl_rule] Globus ACL rule has already been created for request {0}.".format(ridx))
				return {'access_id': myrqst['globus_rid'], 'share_url': myrqst['globus_url']}
			share_data = {'ridx': ridx}
			path = construct_share_path(1, share_data)
		except KeyError as err:
			my_logger.error("[add_endpoint_acl_rule] {0}".format(err), exc_info=True)
			sys.exit(1)

	elif (action == 2):
		try:
			endpoint_id = MyGlobus['datashare_ep']
			dsid = data['dsid']
			cond = " WHERE email='{0}' AND dsid='{1}' AND status='ACTIVE'".format(email, dsid)
			myshare = myget('goshare', ['*'], cond)
			if myshare['globus_rid']:
				my_logger.info("[add_endpoint_acl_rule] Globus ACL rule has already been created for user {0} and dataset {1}.".format(email, dsid))
				return {'access_id': myshare['globus_rid'], 'share_url': myshare['globus_url']}
			share_data = {'dsid': dsid}
			path = construct_share_path(2, share_data)
			share_data.update({'email': email})
		except KeyError as err:
			my_logger.error("[add_endpoint_acl_rule] {0}".format(err), exc_info=True)
			sys.exit(1)

	tc = TransferClient(authorizer=AccessTokenAuthorizer(MyGlobus['transfer_token']))
	identity_id = get_user_id(rda_identity)
	share_data.update({'identity': identity_id})
	
	rule_data = {
	    "DATA_TYPE": "access",
	    "principal_type": "identity",
	    "principal": identity_id,
	    "path": path,
	    "permissions": "r"
 	}
	result = tc.add_endpoint_acl_rule(endpoint_id, rule_data)
	my_logger.info("[add_endpoint_acl_rule] ACL created for user {0}.  ACL ID: {1}".format(email, result['access_id']))
	
	url = construct_share_url(action, share_data)
	share_data.update({'globus_rid': result['access_id'],'globus_url': url})	
	update_share_record(action, share_data)
	
	return {'access_id': result["access_id"], 'share_url': url}

def delete_endpoint_acl_rule(id):
	""" Delete a specific endpoint access rule """ 

def construct_share_path(action, data):
	""" Construct the path to the shared data.  Path is relative to the 
	    shared endpoint base path.
	    
	    action = 1: dsrqst share
	           = 2: standard dataset share
	"""
	if (action == 1):
		try:
			ridx = data['ridx']
			cond = " WHERE rindex='{0}'".format(ridx)
			myrqst = myget('dsrqst', ['rqstid','location'], cond)
			if (len(myrqst) > 0):
				if myrqst['location']:
					base_path = MyGlobus['data_request_ep_base']
					loc = myrqst['location']
					if (loc.find(base_path) != -1):
						path_len = len(base_path)
						path = "/{0}/".format(loc[path_len:])
					else:
						path = None
				else:
					path = "/download.auto/{0}/".format(myrqst['rqstid'])
			else:
				my_logger.error("[construct_share_path] Request index {0} not found or request ID not defined".format(ridx))
		except KeyError as err:
			my_logger.error("[construct_share_path] {0}".format(err), exc_info=True)
			sys.exit(1)
	elif (action == 2):
		try:
			path = "/{0}/".format(data['dsid'])
		except KeyError as err:
			my_logger.error("[construct_share_path] {0}".format(err), exc_info=True)
			sys.exit(1)

	my_logger.info("[construct_share_path] Path to shared data: {0}".format(path))
	return path

def construct_share_url(action, data):
	""" Construct the URL to the shared data on the Globus web app 
	
		action = 1: dsrqst shares
		       = 2: standard dataset share
	"""
	if (action == 1):
		try:
			ridx = data['ridx']
			cond = ' WHERE ridx={0}'.format(ridx)
			myrqst = myget('dsrqst', ['*'], cond)
			if (len(myrqst) > 0):
				origin_id = MyGlobus['data_request_ep']
				origin_path = construct_share_path(1, {'ridx': ridx})
			else:
				my_logger.warning("[construct_share_url] Request {0} not found in RDADB".format(ridx))
				sys.exit(1)
		except KeyError as err:
			my_logger.error("[construct_share_url] {0}".format(err), exc_info=True)
			sys.exit(1)

	if (action == 2):
		try:
			origin_id = MyGlobus['datashare_ep']
			origin_path = construct_share_path(2, {'dsid': data['dsid']})
		except KeyError as err:
			my_logger.error("[construct_share_url] {0}".format(err), exc_info=True)
			sys.exit(1)

	params = {'origin_id': origin_id, 'origin_path': origin_path}
	if 'identity' in data:
		params.update({'add_identity': data['identity']})
	
	url = '{0}transfer?{1}'.format(MyGlobus['globusURL'], urlencode(params))
	
	my_logger.info("[construct_share_url] Globus share URL created: {0}".format(url))
	return url
	
def get_user_id(identity):
	""" Get the UUID assigned by Globus Auth. Input argument 'identity' can be one of
	    the following:
	    
	    GlobusID (Globus primary identity): in the form of user@globusid.org
		NCAR RDA identity                 : in the form of user@domain.com@rda.ucar.edu, where user@domain.com is the user's RDA e-mail login
		E-mail identity                   : in the form of user@domain.com
	"""
	ac = AuthClient(authorizer=AccessTokenAuthorizer(MyGlobus['auth_token']))
	result = ac.get_identities(usernames=identity)
	uuid = result.data['identities'][0]['id']
	
	return uuid

def query_acl_rule(action, data):
	""" Check if an active ACL rule exists for a given RDA user """
	
	if (action == 1):
		""" dsrqst shares """
		try:
			cond = " WHERE rindex='{0}'".format(data['ridx'])
			myrule = myget('dsrqst', ['*'], cond)
		except KeyError as err:
			my_logger.error("[query_acl_rule] {0}".format(err), exc_info=True)
			sys.exit(1)
		
	elif (action == 2):
		""" standard dataset shares """
		try:
			cond = " WHERE email='{0}' AND dsid='{1}' AND status='ACTIVE'".format(data['email'], data['dsid'])
			myrule = myget('goshare', ['*'], cond)
		except:
			my_logger.error("[query_acl_rule] {0}".format(err), exc_info=True)
			sys.exit(1)
	
	if 'globus_rid' in myrule:
		rule_id = myrule['globus_rid']
		return {'acl_rule': rule_id}
	else:
		return None
	
	
def update_share_record(action, data):
	""" Update the user's Globus share in RDADB """
	from datetime import datetime
	from time import strftime
	
	try:
		globus_rid = data['globus_rid']
		globus_url = data['globus_url']
	except KeyError as err:
		my_logger.error("[update_share_record] {0}".format(err), exc_info=True)
		sys.exit(1)
	
	record = []
	
	if (action == 1):
		try:
			ridx = data['ridx']
			cond = " WHERE rindex='{0}'".format(ridx)
			record.append({unicode('globus_rid'): data['globus_rid'],
			               unicode('globus_url'): data['globus_url']
			              })
			myupdt('dsrqst', record[0], cond)
			my_logger.info("[update_share_record] dsrqst record updated. Request index: {0}.  ACL rule ID: {1}.".format(ridx, globus_rid)) 
		except KeyError as err:
			my_logger.error("[update_share_record] {0}".format(err), exc_info=True)
			sys.exit(1) 
	elif (action == 2):
		try:
			dsid = data['dsid']
			email = data['email']
			cond = " WHERE email='{0}' AND end_date IS NULL".format(email)
			myuser = myget('ruser', ['id'], cond)
			if 'id' not in myuser:
				return {'Error': '[update_share_record] email {0} not in RDADB table ruser'.format(email)}
			path = construct_share_path(2, {'dsid': dsid})
			record = {'globus_rid': '{0}'.format(data['globus_rid']),
                      'globus_url': '{0}'.format(data['globus_url']),
                      'email': email,
                      'user_id': '{0}'.format(myuser['id']),
                      'username': None,
                      'request_date': datetime.now().strftime("%Y-%m-%d"),
                      'source_endpoint': MyGlobus['datashare_legacy'],
                      'dsid': '{0}'.format(dsid),
                      'acl_path': '{0}'.format(path),
                      'status': 'ACTIVE'}
			myadd('goshare', record)
			my_logger.info("[update_share_record] Record added to goshare. Email: {0}, dsid: {1}, ACL rule ID: {2}.".format(email, dsid, globus_rid)) 
		except KeyError as e:
			my_logger.error("[update_share_record] {0}".format(err), exc_info=True)
			sys.exit(1)

	return
	
def parse_input():
	""" Parse command line arguments """

def configure_log(**kwargs):
	""" Set up log file """
	LOGPATH = '/glade/p/rda/work/tcram/logs/globus'
	LOGFILE = 'dsglobus.log'

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
	handler = logging.handlers.RotatingFileHandler(LOGPATH+'/'+LOGFILE,maxBytes=200000000,backupCount=10)
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