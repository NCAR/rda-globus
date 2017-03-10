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
                        AuthClient, GlobusError, GlobusAPIError, NetworkError)
from globus_utils import load_app_client
from MyLOG import show_usage
import json
import logging
import logging.handlers
import argparse
import textwrap
import re

try:
    from urllib.parse import urlencode
except:
    from urllib import urlencode

def main():
	opts = parse_input()
	action = opts['action']
	
	if opts['removePermission']:
		result = delete_endpoint_acl_rule(action, opts)
	elif opts['addPermission']:
		result = add_endpoint_acl_rule(action, opts)
	
	return result

def add_endpoint_acl_rule(action, data):
	""" Create a new endpoint access rule """
	try:
		email = data['email']
		rda_identity = "{0}@rda.ucar.edu".format(email)
	except KeyError as err:
		return handle_error(err, name="[add_endpoint_acl_rule]")
	
	if (action == 1):
		try:
			endpoint_id = MyGlobus['data_request_ep']
			ridx = data['ridx']
			cond = " WHERE rindex='{0}'".format(ridx)
			myrqst = myget('dsrqst', ['*'], cond)
			if (len(myrqst) == 0):
				msg = "[add_endpoint_acl_rule] Request index not on file"
				my_logger.warning(msg)
				return {'Error': msg}
			rqstid = myrqst['rqstid']
			if myrqst['globus_rid']:
				my_logger.info("[add_endpoint_acl_rule] Globus ACL rule has already been created for request {0}.".format(ridx))
				return {'access_id': myrqst['globus_rid'], 'share_url': myrqst['globus_url']}
			share_data = {'ridx': ridx}
			path = construct_share_path(1, share_data)
		except KeyError as err:
			return handle_error(err, name="[add_endpoint_acl_rule]")

	elif (action == 2):
		try:
			endpoint_id = MyGlobus['datashare_ep']
			dsid = data['dsid']
			cond = " WHERE email='{0}' AND dsid='{1}' AND status='ACTIVE'".format(email, dsid)
			myshare = myget('goshare', ['*'], cond)
			if (len(myshare) > 0 and myshare['globus_rid']):
				my_logger.info("[add_endpoint_acl_rule] Globus ACL rule has already been created for user {0} and dataset {1}.".format(email, dsid))
				return {'access_id': myshare['globus_rid'], 'share_url': myshare['globus_url']}
			share_data = {'dsid': dsid}
			path = construct_share_path(2, share_data)
			share_data.update({'email': email})
		except KeyError as err:
			return handle_error(err, name="[add_endpoint_acl_rule]")

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
		raise e
	except NetworkError:
		my_logger.error(("[add_endpoint_acl_rule] Network Failure. "
                   "Possibly a firewall or connectivity issue"))
		raise
	except GlobusError:
		logging.exception("[add_endpoint_acl_rule] Totally unexpected GlobusError!")
		raise
    
	my_logger.info("[add_endpoint_acl_rule] {0}. Resource: {1}. Request ID: {2}. Access ID: {3}".format(result['message'], result['resource'], result['request_id'], result['access_id']))
	my_logger.info("[add_endpoint_acl_rule] User email: {0}".format(email))
		
	url = construct_share_url(action, share_data)
	share_data.update({'globus_rid': result['access_id'],'globus_url': url})	
	update_share_record(action, share_data)
	
	return {'access_id': result["access_id"], 'share_url': url}

def delete_endpoint_acl_rule(action, data):
	""" Delete a specific endpoint access rule """ 

	if (action == 1):
		try:
			endpoint_id = MyGlobus['data_request_ep']
			ridx = data['ridx']
			cond = " WHERE rindex='{0}'".format(ridx)
			myrqst = myget('dsrqst', ['*'], cond)
			if (len(myrqst) == 0):
				msg = "[delete_endpoint_acl_rule] Request index not on file"
				my_logger.warning(msg)
				return {'Error': msg}
			if not myrqst['globus_rid']:
				msg = "[delete_endpoint_acl_rule] Globus ACL rule not found in request record (request index {0}).".format(ridx)
				my_logger.warning(msg)
				return {'Error': msg}
			else:
				rule_id = myrqst['globus_rid']
		except KeyError as err:
			return handle_error(err, name="[delete_endpoint_acl_rule]")

	elif (action == 2):
		try:
			endpoint_id = MyGlobus['datashare_ep']
			email = data['email']
			dsid = data['dsid']
			cond = " WHERE email='{0}' AND dsid='{1}' AND status='ACTIVE'".format(email, dsid)
			myshare = myget('goshare', ['*'], cond)
			if (len(myshare) == 0):
				msg = "[delete_endpoint_acl_rule] Globus share record not found for e-mail = {0} and dsid = {1}.".format(email, dsid)
				my_logger.warning(msg)
				return {'Error': msg}
			if not myrqst['globus_rid']:
				msg = "[delete_endpoint_acl_rule] Globus ACL rule not found in Globus share record (e-mail: {0}, dsid: {1}).".format(email, dsid)
				my_logger.warning(msg)
				return {'Error': msg}
			else:
				rule_id = myshare['globus_rid']
				record = []
				record.append({unicode('delete_date'): date,
				               unicode('status'): 'DELETED'
				               })
				myupdt('goshare', record[0], cond)
		except KeyError as err:
			return handle_error(err, name="[delete_endpoint_acl_rule]")

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
    
	msg = "[delete_endpoint_acl_rule] {0}. Resource: {1}. Request ID: {2}.".format(result['message'], result['resource'], result['request_id'])
	my_logger.info(msg)
	
	return msg

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
				msg = "[construct_share_path] Request index {0} not found or request ID not defined".format(ridx)
				my_logger.error(msg)
				return {'Error': msg}
		except KeyError as err:
			return handle_error(err, name="[construct_share_path]")
	elif (action == 2):
		try:
			path = "/{0}/".format(data['dsid'])
		except KeyError as err:
			return handle_error(err, name="[construct_share_path]")

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
			cond = ' WHERE rindex={0}'.format(ridx)
			myrqst = myget('dsrqst', ['*'], cond)
			if (len(myrqst) > 0):
				origin_id = MyGlobus['data_request_ep']
				origin_path = construct_share_path(1, {'ridx': ridx})
			else:
				msg = "[construct_share_url] Request {0} not found in RDADB".format(ridx)
				my_logger.warning(msg)
				return {'Error': msg}
		except KeyError as err:
			return handle_error(err, name="[construct_share_url]")

	if (action == 2):
		try:
			origin_id = MyGlobus['datashare_ep']
			origin_path = construct_share_path(2, {'dsid': data['dsid']})
		except KeyError as err:
			return handle_error(err, name="[construct_share_url]")

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
	try:
		ac = AuthClient(authorizer=AccessTokenAuthorizer(MyGlobus['auth_token']))
		result = ac.get_identities(usernames=identity)
		uuid = result.data['identities'][0]['id']
	except GlobusAPIError as e:
		my_logger.error(("[get_user_id] Globus API Error\n"
		                 "HTTP status: {}\n"
		                 "Error code: {}\n"
		                 "Error message: {}").format(e.http_status, e.code, e.message))
		raise e
	except NetworkError:
		my_logger.error(("[get_user_id] Network Failure. "
                   "Possibly a firewall or connectivity issue"))
		raise
	except GlobusError:
		logging.exception("[get_user_id] Totally unexpected GlobusError!")
		raise

	return uuid

def query_acl_rule(action, data):
	""" Check if an active ACL rule exists for a given RDA user """
	
	if (action == 1):
		""" dsrqst shares """
		cond = " WHERE rindex='{0}'".format(data['ridx'])
		myrule = myget('dsrqst', ['*'], cond)
		
	elif (action == 2):
		""" standard dataset shares """
		cond = " WHERE email='{0}' AND dsid='{1}' AND status='ACTIVE'".format(data['email'], data['dsid'])
		myrule = myget('goshare', ['*'], cond)
	
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
		return handle_error(err, name="[update_share_record]")
	
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
			return handle_error(err, name="[update_share_record]") 
	elif (action == 2):
		try:
			dsid = data['dsid']
			email = data['email']
			cond = " WHERE email='{0}' AND end_date IS NULL".format(email)
			myuser = myget('ruser', ['id'], cond)
			if 'id' not in myuser:
				msg = "[update_share_record] email {0} not in RDADB table ruser".format(email)
				my_logger.warning(msg)
				return {'Error': msg}
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
		except KeyError as err:
			return handle_error(err, name="[update_share_record]")

	return
	
def parse_input():
	""" Parse command line arguments """
	desc = "Manage RDA Globus shared endpoints and endpoint permissions."	
	epilog = textwrap.dedent('''\
	Examples:
	  - Grant permission to a user for dsrqst index 1234:
	              dsglobus -ap -ri 1234
	
	  - Delete permission from a user and delete the access share rule for dsrqst index 1234:
	              dsglobus -rp -ri 1234
	
	  - Share all files from RDA dataset ds131.2 with a user:
	             dsglobus -ap -ds 131.2 -em tcram@ucar.edu
	''')

	parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=desc, epilog=textwrap.dedent(epilog))

	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('-ap', action="store_true", default=False, help='Add endpoint permission')
	group.add_argument('-rp', action="store_true", default=False, help='Delete endpoint permission')

	parser.add_argument('-ri', action="store", dest="REQUESTINDEX", type=int, help='dsrqst request index')
	parser.add_argument('-ds', action="store", dest="DATASETID", help='Dataset ID.  Specify as dsnnn.n or nnn.n.  Used together with the -em argument.')
	parser.add_argument('-em', action="store", dest="EMAIL", help='User e-mail.  Used together with the -ds argument.')
	parser.add_argument('-ne', action="store_true", default=False, help='Do not send notification e-mail.  Default = False.')
		
	parser = argparse.ArgumentParser(description="{}".format(sys.argv[0]))
	parser.add_argument('-ri', action="store", dest="ri", type=int)
	parser.add_argument('-ds', action="store", dest="ds")
	parser.add_argument('-em', action="store", dest="em")
	parser.add_argument('-ap', action="store_true", default=False)
	parser.add_argument('-rp', action="store_true", default=False)
	parser.add_argument('-ne', action="store_true", default=False)
	parser.add_argument('-h', action="store", dest="h")
	args = parser.parse_args(sys.argv[1:])
	my_logger.info("{0}: {1}".format(sys.argv[0], args)
	
	opts = vars(args)

	if (opts['REQUESTINDEX'] and opts['DATASETID']):
		msg = "Please specify only one of: dsrqst index (-ri) or dataset ID (-ds), not both."
		my_logger.error(msg)
		print msg
		sys.exit(1)
 	if opts['REQUESTINDEX']:
		opts['ridx'] = options.pop('REQUESTINDEX')
		opts.update({'action': 1})
	elif opts['DATASETID']:
		if not opts['EMAIL']:
			msg = "Please specify user e-mail via the -em option."
			my_logger.error(msg)
			print msg
			sys.exit(1)
		dsid = opts['DATASETID']
		searchObj = re.search(r'^\d+\.\d+$', dsid)
		if searchObj:
			dsid = "ds%s" % dsid
		if not re.match(r'^(ds){0,1}\d+\.\d+$', dsid, re.I):
			msg = "Please specify the dataset id as dsnnn.n or nnn.n"
			my_logger.error(msg)
			print msg
			sys.exit(1)
		opts['dsid'] = opts.pop('DATASETID').lower()
		opts['email'] = opts.pop('EMAIL')
		opts.update({'action': 2})
	elif opts['EMAIL']:
		msg = "Please specify the dataset ID via the -ds option."
		my_logger.error(msg)
		print msg
		sys.exit(1)
	else:
		parser.print_help()
		sys.exit(1)

	return opts
	
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

def handle_error(err, **kwargs):
	if 'name' in kwargs:
		name = kwargs['function']
	else:
		name = ""
	
	msg = "{0} {1}".format(name, err)
	my_logger.error(msg, exc_info=True)
	
	return {'Error': msg}

#=========================================================================================
""" Set up logging """
my_logger = logging.getLogger(__name__)
configure_log(level='info')

if __name__ == "__main__":
    main()