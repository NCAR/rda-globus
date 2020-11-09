#!/usr/bin/env python3
#
##################################################################################
#
#     Title : dsglobus.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 02/17/2017
#   Purpose : Python module to create and manage shared endpoints to facilitate
#             Globus data transfers from the RDA.
#
# Work File : $DSSHOME/lib/python/dsglobus.py*
# Test File : $DSSHOME/lib/python/dsglobus_test.py*
# Github    : https://github.com/NCAR/rda-globus/python/dsglobus.py
#
##################################################################################

import os, sys
import subprocess

try:
	assert sys.version_info >= (3,0)
except AssertionError:
	print ("Error: Python version 3.0+ required.")
	raise

path1 = "/glade/u/home/rdadata/lib/python"
path2 = "/glade/u/home/tcram/lib/python"
if (path1 not in sys.path):
	sys.path.append(path1)
if (path2 not in sys.path):
	sys.path.append(path2)

import argparse
import logging
import logging.handlers
import json
import textwrap
import six
from datetime import datetime
from time import strftime
from phpserialize import unserialize
try:
    from urllib.parse import urlencode
except:
    from urllib import urlencode

from MyLOG import show_usage
from PyDBI import myget, myupdt, myadd, mymget
from MyGlobus import MyGlobus, MyEndpoints

from globus_sdk import (TransferClient, TransferAPIError,
                        TransferData, RefreshTokenAuthorizer, AuthClient, 
                        GlobusError, GlobusAPIError, NetworkError)
from globus_utils import load_app_client, load_rda_native_client

#=========================================================================================
def main(json_input = None):
	if json_input:
		result = do_action(json_input)
	else:
		opts = parse_input()
		result = do_action(opts)	

	return result

#=========================================================================================
def add_endpoint_acl_rule(data):
	""" Create a new endpoint access rule.  'type' must be defined in the input dict:
	    type = 'dsrqst':  dsrqst share
	         = 'dataset': standard dataset share
	"""
	if 'print' in data:
		print_stdout = data['print']
	else:
		print_stdout = False
	
	try:
		type = data['type']
	except KeyError:
		msg = "[add_endpoint_acl_rule] 'type' not defined in input dict."
		my_logger.error(msg)
		sys.exit(1)
		
	if (type == 'dsrqst'):
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
			if myrqst['globus_rid']:
				msg = "[add_endpoint_acl_rule] Globus ACL rule has already been created for request {0}.".format(ridx)
				my_logger.info("msg")
				if 'print' in data and data['print']:
					sys.exit(msg)
				return {'access_id': myrqst['globus_rid'], 'share_url': myrqst['globus_url']}
			share_data = {'ridx': ridx, 'dsid': dsid, 'email': email}
			path = construct_share_path(type, share_data)
		except KeyError as err:
			return handle_error(err, name="[add_endpoint_acl_rule]", print_stdout=print_stdout)

	elif (type == 'dataset'):
		try:
			endpoint_id = MyGlobus['datashare_ep']
			dsid = data['dsid']
			email = data['email']
			cond = " WHERE email='{0}' AND dsid='{1}' AND status='ACTIVE'".format(email, dsid)
			myshare = myget('goshare', ['*'], cond)
			if (len(myshare) > 0 and myshare['globus_rid']):
				msg = "[add_endpoint_acl_rule] Globus ACL rule has already been created for user {0} and dataset {1}. ACL rule {2}".format(email, dsid, myshare['globus_rid'])
				my_logger.info(msg)
				if 'print' in data and data['print']:
					sys.exit(msg)
				return {'access_id': myshare['globus_rid'], 'share_url': myshare['globus_url']}
			share_data = {'dsid': dsid}
			path = construct_share_path(type, share_data)
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
		tc_authorizer = RefreshTokenAuthorizer(MyGlobus['transfer_refresh_token'], load_app_client())
		tc = TransferClient(authorizer=tc_authorizer)
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
	
	msg = "{0}\nResource: {1}\nRequest ID: {2}\nAccess ID: {3}".format(result['message'], result['resource'], result['request_id'], result['access_id'])
	if 'print' in data and data['print']:
		print (msg)
	my_logger.info("[add_endpoint_acl_rule] {0}".format(msg))
	my_logger.info("[add_endpoint_acl_rule] User email: {0}".format(email))
	
	if 'print' in data and data['print']:
		share_data.update({'print': True})
	
	url = construct_share_url(type, share_data)
	share_data.update({'globus_rid': result['access_id'],'globus_url': url})	
	update_share_record(type, share_data)
	
	return {'access_id': result["access_id"], 'share_url': url}

#=========================================================================================
def delete_endpoint_acl_rule(data):
	""" Delete a specific endpoint access rule. 'type' must be defined in input dict:
	    type = 'dsrqst':  dsrqst share
	         = 'dataset': standard dataset share
	""" 
	if 'print' in data:
		print_stdout = data['print']
	else:
		print_stdout = False

	try:
		type = data['type']
	except KeyError:
		msg = "[delete_endpoint_acl_rule] 'type' not defined in input dict."
		my_logger.error(msg)
		sys.exit(1)

	if (type == 'dsrqst'):
		try:
			endpoint_id = MyGlobus['data_request_ep']
			ridx = data['ridx']
		except KeyError as err:
			return handle_error(err, name="[delete_endpoint_acl_rule]", print_stdout=print_stdout)
		else:
			rqst_cond = " WHERE rindex='{0}'".format(ridx)

			""" Try the dsrqst record first, then try dspurge """
			myrqst = myget('dsrqst', ['*'], rqst_cond)
			mypurge = myget('dspurge', ['*'], rqst_cond)
			rqst_rid = None
			purge_rid = None
			
			try:
				rqst_rid = myrqst['globus_rid']
			except KeyError:
				try:
					purge_rid = mypurge['globus_rid']
				except KeyError:
					msg = "[delete_endpoint_acl_rule] Request record not found in dsrqst or dspurge (request index {0}).".format(ridx)
					my_logger.warning(msg)
					if 'print' in data and data['print']:
						sys.exit("Error: {0}".format(msg))
					return {'Error': msg}

			rule_id = rqst_rid if rqst_rid else purge_rid
			
			if not rule_id:
				msg = "[delete_endpoint_acl_rule] Globus ACL rule not found in request record (request index {0}).".format(ridx)
				my_logger.warning(msg)
				if 'print' in data and data['print']:
					sys.exit("Error: {0}".format(msg))
				return {'Error': msg}
			else:
				record = {'globus_rid': None,
				          'globus_url': None}
				if rqst_rid:
					myupdt('dsrqst', record, rqst_cond)
				else:
					myupdt('dspurge', record, rqst_cond)
				
				share_cond = " WHERE rindex='{0}' AND status='ACTIVE'".format(ridx)
				myshare = myget('goshare', ['*'], share_cond)
				if (len(myshare) > 0):
					share_record = {'delete_date': datetime.now().strftime("%Y-%m-%d"),
				                    'status': 'DELETED'}
					myupdt('goshare', share_record, share_cond)

	elif (type == 'dataset'):
		try:
			endpoint_id = MyGlobus['datashare_ep']
			email = data['email']
			dsid = data['dsid']
		except KeyError as err:
			return handle_error(err, name="[delete_endpoint_acl_rule]", print_stdout=print_stdout)
		else:
			cond = " WHERE email='{0}' AND dsid='{1}' AND status='ACTIVE'".format(email, dsid)
			myshare = myget('goshare', ['*'], cond)
			if (len(myshare) == 0):
				msg = "[delete_endpoint_acl_rule] Globus share record not found for e-mail = {0} and dsid = {1}.".format(email, dsid)
				my_logger.warning(msg)
				if 'print' in data and data['print']:
					sys.exit("Error: {0}".format(msg))
				return {'Error': msg}
			if not myshare['globus_rid']:
				msg = "[delete_endpoint_acl_rule] Globus ACL rule not found in Globus share record (e-mail: {0}, dsid: {1}).".format(email, dsid)
				my_logger.warning(msg)
				if 'print' in data and data['print']:
					sys.exit("Error: {0}".format(msg))
				return {'Error': msg}
			else:
				rule_id = myshare['globus_rid']
				record = {'delete_date': datetime.now().strftime("%Y-%m-%d"),
				          'status': 'DELETED'}
				myupdt('goshare', record, cond)

	try:
		tc_authorizer = RefreshTokenAuthorizer(MyGlobus['transfer_refresh_token'], load_app_client())
		tc = TransferClient(authorizer=tc_authorizer)
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
	if 'print' in data and data['print']:
		print (msg)
	my_logger.info("[delete_endpoint_acl_rule] {0}".format(msg))
	
	return msg

#=========================================================================================
def submit_dsrqst_transfer(data):
	""" Submit a Globus transfer on behalf of the user.  For dsrqst 'push' transfers. """

	""" Get session ID from dsrqst record """
	ridx = data['ridx']
	cond = " WHERE rindex={0}".format(ridx)
	myrqst = myget('dsrqst', ['tarcount', 'tarflag', 'session_id'], cond)
	if (len(myrqst) == 0):
		msg = "[submit_dsrqst_transfer] Request index not found in DB"
		my_logger.warning(msg)
		sys.exit(1)

	session = get_session(myrqst['session_id'])
	email = session['email']
	dsid = session['dsid']
	type = 'dsrqst'
	
	""" Define source endpoint ID and paths """
	host_endpoint = MyGlobus['host_endpoint_id']
	source_endpoint_id = MyGlobus['data_request_ep']
	destination_endpoint_id = session['endpoint_id']

	""" Check if user has a share set up for this endpoint & path """
	share_data = {'ridx': ridx, 'notify': True}
	if not query_acl_rule(type, share_data):
		acl_data = add_endpoint_acl_rule(1, share_data)
	directory = construct_share_path(type, share_data)

	""" Instantiate the Globus SDK transfer client """
	refresh_token = session['transfer.api.globus.org']['refresh_token']
	tc_authorizer = RefreshTokenAuthorizer(refresh_token, load_app_client())
	transfer = TransferClient(authorizer=tc_authorizer)
        
	""" Instantiate TransferData object """
	transfer_data = TransferData(transfer_client=transfer,
								 source_endpoint=source_endpoint_id,
								 destination_endpoint=destination_endpoint_id,
								 label=session['label'])

	""" Check for tar file output and add to items to be transferred. 
	    Note that source_path is relative to the source endpoint base path. """

	ep_base_path = MyGlobus['data_request_ep_base'].rstrip("/")

	if (myrqst['tarflag'] == 'Y' and myrqst['tarcount'] > 0):
		tar_dir = 'TarFiles'
		if os.path.exists(ep_base_path + directory + tar_dir):
			source_path = directory + tar_dir
			dest_path = session['dest_path'] + tar_dir
			transfer_data.add_item(source_path, dest_path, recursive=True)

	""" Get individual request files from wfrqst and add to items to be transferred """
	
	files = mymget('wfrqst', ['wfile'], "{} ORDER BY disp_order, wfile".format(cond))

	if (len(files) > 0):
		for i in range(len(files)):
			file = files[i]['wfile']
			if os.path.isfile(ep_base_path + directory + file):
				source_path = directory + file
				dest_path = session['dest_path'] + file
				transfer_data.add_item(source_path, dest_path)

	if (len(transfer_data['DATA']) == 0):
		my_logger.warning("[submit_dsrqst_transfer] No request files found to transfer for request index {}".format(ridx))
		return None

	transfer.endpoint_autoactivate(source_endpoint_id)
	transfer.endpoint_autoactivate(destination_endpoint_id)
	task_id = transfer.submit_transfer(transfer_data)['task_id']

	""" Store task_id in request record """
	record = [{'task_id': task_id}]
	myupdt('dsrqst', record[0], cond)
	
	msg = "[submit_dsrqst_transfer] Transfer submitted successfully.  Task ID: {0}. Files transferred: {1}.  Request index: {2}".format(task_id, len(transfer_data['DATA']), ridx)
	my_logger.info(msg)
	
	if 'print' in data and data['print']:
		print ("{}".format(task_id))

	"""	Create share record in goshare """

	return task_id
	
#=========================================================================================
def construct_share_path(type, data):
	""" Construct the path to the shared data.  Path is relative to the 
	    shared endpoint base path.
	    
	    type = 'dsrqst': dsrqst share
	         = 'dataset': standard dataset share
	"""
	if 'print' in data:
		print_stdout = data['print']
	else:
		print_stdout = False

	if (type == 'dsrqst'):
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
				if 'print' in data and data['print']:
					sys.exit("Error: {0}".format(msg))
				return {'Error': msg}
		except KeyError as err:
			return handle_error(err, name="[construct_share_path]", print_stdout=print_stdout)
	elif (type == 'dataset'):
		try:
			path = "/{0}/".format(data['dsid'])
		except KeyError as err:
			return handle_error(err, name="[construct_share_path]", print_stdout=print_stdout)

	my_logger.info("[construct_share_path] Path to shared data: {0}".format(path))
	return path

#=========================================================================================
def construct_share_url(type, data):
	""" Construct the URL to the shared data on the Globus web app 
	
		type = 'dsrqst': dsrqst shares
		     = 'dataset': standard dataset share
	"""
	if 'print' in data:
		print_stdout = data['print']
	else:
		print_stdout = False

	if (type == 'dsrqst'):
		try:
			ridx = data['ridx']
			cond = ' WHERE rindex={0}'.format(ridx)
			myrqst = myget('dsrqst', ['*'], cond)
			if (len(myrqst) > 0):
				origin_id = MyGlobus['data_request_ep']
				origin_path = construct_share_path(type, {'ridx': ridx})
			else:
				msg = "[construct_share_url] Request {0} not found in RDADB".format(ridx)
				my_logger.warning(msg)
				if 'print' in data and data['print']:
					sys.exit("Error: {0}".format(msg))
				return {'Error': msg}
		except KeyError as err:
			return handle_error(err, name="[construct_share_url]", print_stdout=print_stdout)

	if (type == 'dataset'):
		try:
			origin_id = MyGlobus['datashare_ep']
			origin_path = construct_share_path(type, {'dsid': data['dsid']})
		except KeyError as err:
			return handle_error(err, name="[construct_share_url]", print_stdout=print_stdout)

	params = {'origin_id': origin_id, 'origin_path': origin_path}
	if 'identity' in data:
		params.update({'add_identity': data['identity']})
	
	url = '{0}transfer?{1}'.format(MyGlobus['globusURL'], urlencode(params))
	
	my_logger.info("[construct_share_url] Globus share URL created: {0}".format(url))
	return url
	
#=========================================================================================
def get_user_id(identity):
	""" Get the UUID assigned by Globus Auth. Input argument 'identity' can be one of
	    the following:
	    
	    GlobusID (Globus primary identity): in the form of user@globusid.org
		NCAR RDA identity                 : in the form of user@domain.com@rda.ucar.edu, where user@domain.com is the user's RDA e-mail login
		E-mail identity                   : in the form of user@domain.com
	"""
	try:
		ac_authorizer = RefreshTokenAuthorizer(MyGlobus['auth_refresh_token'], load_app_client())
		ac = AuthClient(authorizer=ac_authorizer)
		result = ac.get_identities(usernames=identity, provision=True)
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

#=========================================================================================
def query_acl_rule(type, data):
	""" Check if an active ACL rule exists for a given RDA user
	    type = 'dsrqst': dsrqst share
	         = 'dataset': standard dataset share
	"""
	if 'print' in data:
		print_stdout = data['print']
	else:
		print_stdout = False
	
	if (type == 'dsrqst'):
		""" dsrqst shares """
		cond = " WHERE rindex='{0}'".format(data['ridx'])
		myrule = myget('dsrqst', ['*'], cond)
		
	elif (type == 'dataset'):
		""" standard dataset shares """
		cond = " WHERE email='{0}' AND dsid='{1}' AND status='ACTIVE'".format(data['email'], data['dsid'])
		myrule = myget('goshare', ['*'], cond)

	try:
		rule_id = myrule['globus_rid']
	except KeyError:
		rule_id = None

	if rule_id:
		return {'acl_rule': rule_id}
	else:
		return None

#=========================================================================================
def update_share_record(type, data):
	""" Update the user's Globus share in RDADB
	    type = 'dsrqst': dsrqst share
	         = 'dataset': standard dataset share
	"""
	if ('print' in data):
		print_stdout = data['print']
	else:
		print_stdout = False

	try:
		globus_rid = data['globus_rid']
		globus_url = data['globus_url']
		dsid = data['dsid']
		email = data['email']
		cond = " WHERE email='{0}' AND end_date IS NULL".format(email)
		myuser = myget('ruser', ['id'], cond)
		if 'id' not in myuser:
			msg = "[update_share_record] email {0} not in RDADB table ruser".format(email)
			my_logger.warning(msg)
			return {'Error': msg}
	except KeyError as err:
		return handle_error(err, name="[update_share_record]", print_stdout=print_stdout)
	
	share_record = {'globus_rid': '{0}'.format(globus_rid),
                    'globus_url': '{0}'.format(globus_url),
                    'email': '{0}'.format(email),
                    'user_id': '{0}'.format(myuser['id']),
                    'username': None,
                    'request_date': datetime.now().strftime("%Y-%m-%d"),
                    'dsid': '{0}'.format(dsid),
                    'status': 'ACTIVE'}
	
	if (type == 'dsrqst'):
		try:
			ridx = data['ridx']
			cond = " WHERE rindex='{0}'".format(ridx)
			rqst_record = {'globus_rid': data['globus_rid'],
			               'globus_url': data['globus_url']
			              }
			myupdt('dsrqst', rqst_record, cond)
			my_logger.info("[update_share_record] dsrqst record updated. Request index: {0}.  ACL rule ID: {1}.".format(ridx, globus_rid))
			path = construct_share_path(type, {'ridx': ridx})
			share_record.update({'source_endpoint': '{0}'.format(MyGlobus['data_request_legacy']),
			                     'acl_path': '{0}'.format(path),
			                     'rindex': '{0}'.format(ridx)
			                    })
			myadd('goshare', share_record)
			my_logger.info("[update_share_record] Record added to goshare. Request index: {0}, ACL rule ID: {1}.".format(ridx, globus_rid)) 
		except KeyError as err:
			return handle_error(err, name="[update_share_record]", print_stdout=print_stdout) 
	elif (type == 'dataset'):
		try:
			path = construct_share_path(type, {'dsid': dsid})
			share_record.update({'source_endpoint': '{0}'.format(MyGlobus['datashare_legacy']),
			                     'acl_path': '{0}'.format(path)
			                    })
			myadd('goshare', share_record)
			my_logger.info("[update_share_record] Record added to goshare. Email: {0}, dsid: {1}, ACL rule ID: {2}.".format(email, dsid, globus_rid)) 
		except KeyError as err:
			return handle_error(err, name="[update_share_record]", print_stdout=print_stdout)

	return
	
#=========================================================================================
def get_session(sid):
	""" Retrieve session data from RDADB """
	keys = ['id','access','data']
	condition = " WHERE {0} = '{1}'".format("id", sid)
	myrec = myget('sessions', keys, condition)
	
	if (len(myrec) == 0):
		msg = "[get_session] Session ID not found in DB"
		my_logger.warning(msg)
		sys.exit(1)

	return unserialize(myrec['data'])

#=========================================================================================
def submit_rda_transfer(data):
	""" General data transfer to RDA endpoints.  Input should be JSON formatted input 
	    if transferring multiple files. """

	client_id = get_client_id(data)
	tokens = get_tokens(client_id)
	transfer_refresh_token = tokens['transfer_rt']
	auth_refresh_token = tokens['auth_rt']

	source_endpoint = get_endpoint_by_name(data['source_endpoint'])
	destination_endpoint = get_endpoint_by_name(data['destination_endpoint'])	

	try:
		label = data['label']
	except KeyError:
		label=''

	try:
		files = data['files']
	except KeyError:
		msg = "[submit_rda_transfer] Files missing from JSON or command-line input"
		my_logger.error(msg)
		sys.exit(1)

	client = load_rda_native_client(client_id)
	tc_authorizer = RefreshTokenAuthorizer(transfer_refresh_token, client)
	tc = TransferClient(authorizer=tc_authorizer)
	
	transfer_data = TransferData(transfer_client=tc,
							     source_endpoint=source_endpoint,
							     destination_endpoint=destination_endpoint,
							     label=label)

	for i in range(len(files)):
		source_file = files[i]['source_file']
		dest_file = files[i]['destination_file']
		
		# Verify source file exists and meets minimum size requirements (> 200 MB, 1 GB preferred)    	
		
		transfer_data.add_item(source_file, dest_file)

	try:
		transfer_result = tc.submit_transfer(transfer_data)
		task_id = transfer_result['task_id']
	except GlobusAPIError as e:
		msg = ("[submit_rda_transfer] Globus API Error\n"
		       "HTTP status: {}\n"
		       "Error code: {}\n"
		       "Error message: {}").format(e.http_status, e.code, e.message)
		my_logger.error(msg)
		raise e
	except NetworkError:
		my_logger.error(("[submit_rda_transfer] Network Failure. "
                   "Possibly a firewall or connectivity issue"))
		raise
	except GlobusError:
		logging.exception("[submit_rda_transfer] Totally unexpected GlobusError!")
		raise
	
	msg = "{0}\nTask ID: {1}".format(transfer_result['message'], task_id)
	my_logger.info(msg)
	print(msg)
	
	return transfer_result

#=========================================================================================
def get_endpoint_by_name(endpoint_name):

	try:
		endpoint_id = MyEndpoints[endpoint_name]
	except KeyError:
		msg = "[get_endpoint_id] Unknown endpoint name: {}".format(endpoint_name)
		my_logger.error(msg)
		sys.exit(1)
	
	return endpoint_id

#=========================================================================================
def get_client_id(data):
	""" Get valid client ID based on command-line or JSON input action """

	action = data['action']
	
	client_map = {
			"ap": "client-id",
			"rp": "client-id",
			"st": "client-id",
			"ls": "rda_quasar_client_id",
			"transfer": "rda_quasar_client_id",
			"tb": "rda_quasar_client_id",
			"dr": "rda_quasar_client_id",
			"tb-quasar" : "rda_quasar_client_id",
			"dr-quasar" : "rda_quasar_client_id",
			"gt": "rda_quasar_client_id",
			"tl": "rda_quasar_client_id"
	}

	if action in client_map:
		client_id = MyGlobus[client_map[action]]
	else:
		msg = "[get_client_id] Unknown action.  Cannot map to valid client ID."
		my_logger.error(msg)
		sys.exit(1)

	return client_id

#=========================================================================================
def get_tokens(client_id):
	if client_id == MyGlobus['rda_quasar_client_id']:
		transfer_rt = MyGlobus['transfer_rt_quasar']
		auth_rt = MyGlobus['auth_rt_quasar']
	elif client_id == MyGlobus['client_id']:
		transfer_rt = MyGlobus['transfer_refresh_token']
		auth_rt = MyGlobus['auth_refresh_token']
	else:
		msg = "[get_tokens] Unknown client ID"
		my_logger.error(msg)
		sys.exit(1)

	tokens = {'transfer_rt': transfer_rt,
	          'auth_rt': auth_rt}

	return tokens

#=========================================================================================
def get_task_info(data):
	""" Get Globus task info for a specified task ID """
	if 'task_id' not in data:
		msg = "[get_task_info] Task ID missing from input."
		my_logger.error(msg)
		sys.exit(1)

	client_id = MyGlobus['rda_quasar_client_id']
	tokens = get_tokens(client_id)
	transfer_refresh_token = tokens['transfer_rt']
	
	client = load_rda_native_client(client_id)
	tc_authorizer = RefreshTokenAuthorizer(transfer_refresh_token, client)
	tc = TransferClient(authorizer=tc_authorizer)
	
	task_info = tc.get_task(data['task_id'])
	
	common_fields = [
    	("Label", "label"),
		("Task ID", "task_id"),
		("Is Paused", "is_paused"),
		("Type", "type"),
		("Directories", "directories"),
		("Files", "files"),
		("Status", "status"),
		("Request Time", "request_time"),
	]
	active_fields = [("Deadline", "deadline"), ("Details", "nice_status")]
	completed_fields = [("Completion Time", "completion_time")]
	delete_fields = [
		("Endpoint", "source_endpoint_display_name"),
		("Endpoint ID", "source_endpoint_id"),
	]
	transfer_fields = [
		("Source Endpoint", "source_endpoint_display_name"),
		("Source Endpoint ID", "source_endpoint_id"),
		("Destination Endpoint", "destination_endpoint_display_name"),
		("Destination Endpoint ID", "destination_endpoint_id"),
		("Bytes Transferred", "bytes_transferred"),
		("Bytes Per Second", "effective_bytes_per_second"),
	]
	successful_transfer_fields = [
		("Source Path", "source_path"),
		("Destination Path", "destination_path"),
	]

	fields = (common_fields
			  + (completed_fields if task_info["completion_time"] else active_fields)
			  + (delete_fields if task_info["type"] == "DELETE" else transfer_fields)			  
			  )

	print(fields:\n{}.format(fields))
	
	print_table(task_info, fields)

	"""
	for field in common_fields:
		print("{0}:\t{1}".format(field[0], task_info[field[1]]))
	
	if task_info['status'] == 'SUCCEEDED':
		for field in completed_fields:
			print("{0}:\t{1}".format(field[0], task_info[field[1]]))

	if task_info['type'] == 'TRANSFER':
		for field in transfer_fields:
			print("{0}:\t{1}".format(field[0], task_info[field[1]]))

	if task_info['type'] == 'DELETE':
		for field in delete_fields:
			print("{0}:\t{1}".format(field[0], task_info[field[1]]))
	"""
	
	return task_info.data

#=========================================================================================
def task_list(data):
	""" Get a list of Globus tasks submitted by the current user

	The parameter 'limit' can be passed in the input dict 'data' to limit the number of 
	results, e.g. data['limit'] = 10.
	
	=== Filtering
	The following parameters can be included in the input dict 'data' to filter the results:
	
	filter_task_id: Comma separated list of task IDs, formatted as UUID strings
	filter_type:    Comma separated list of task type (TRANSFER, DELETE)
	filter_status:  Comma separated list of status codes (ACTIVE, INACTIVE, FAILED, SUCCEEDED)
	filter_requested_before: Filter results to tasks submitted before given date, formatted as YYYY-MM-DD
	filter_requested_after:  Filter results to tasks submitted after given date, formatted as YYYY-MM-DD
	filter_completed_before: Filter results to tasks completed before given date, formatted as YYYY-MM-DD
	filter_completed_after:  Filter results to tasks completed after given date, formatted as YYYY-MM-DD
	"""
	
	client_id = MyGlobus['rda_quasar_client_id']
	tokens = get_tokens(client_id)
	transfer_refresh_token = tokens['transfer_rt']
	
	client = load_rda_native_client(client_id)
	tc_authorizer = RefreshTokenAuthorizer(transfer_refresh_token, client)
	tc = TransferClient(authorizer=tc_authorizer)
	
	limit = data['limit']

	# make filter string
	filter_string = ""
	try:
		filter_task_id = data['filter_task_id']
		filter_string += process_filterval("task_id", filter_task_id)
	except KeyError:
		pass
	try:
		filter_status = data['filter_status']
		filter_string += process_filterval("status", filter_status)
	except KeyError:
		pass
	try:
		filter_type = data['filter_type']
		filter_string += process_filterval("type", filter_type, default="type:TRANSFER,DELETE/")
	except KeyError:
		pass
	
	try:
		filter_requested_before = data['filter_requested_before']
		if not filter_requested_before:
			filter_requested_before = ""
	except KeyError:
		filter_requested_before = ""

	try:
		filter_requested_after = data['filter_requested_after']
		if not filter_requested_after:
			filter_requested_after = ""
	except KeyError:
		filter_requested_after = ""

	try:
		filter_completed_before = data['filter_completed_before']
		if not filter_completed_before:
			filter_completed_before = ""
	except KeyError:
		filter_completed_before = ""

	try:
		filter_completed_after = data['filter_completed_after']
		if not filter_completed_after:
			filter_completed_after = ""
	except KeyError:
		filter_completed_after = ""
	
	if (filter_requested_before or filter_requested_after):
		filter_string += process_filterval(
			"request_time", [filter_requested_after, filter_requested_before]
		)
	if (filter_completed_before or filter_completed_after):
		filter_string += process_filterval(
			"completion_time", [filter_completed_after, filter_completed_before]
		)

	fields = [
		("Task ID", "task_id"),
		("Status", "status"),
		("Type", "type"),
		("Source Display Name", "source_endpoint_display_name"),
		("Dest Display Name", "destination_endpoint_display_name"),
		("Request Time", "request_time"),
		("Completion Time", "completion_time"),
		("Label", "label")
	]

	list_response = tc.task_list(num_results=limit, filter=filter_string[:-1])
	print_table(list_response, fields)

	return list_response

#=========================================================================================
def process_filterval(prefix, value, default=None):
	""" Create filter string for task_list """
	if value:
		if isinstance(value, six.string_types):
			return "{}:{}/".format(prefix, value)
		return "{}:{}/".format(prefix, ",".join(str(x) for x in value))
	else:
		return default or ""
            
#=========================================================================================
def list_endpoint_files(data):
	""" List endpoint directory contents 
	
	=== Filtering
	List files and dirs on a specific path on an endpoint, filtering in various ways.

    Filter patterns must start with "=", "~", "!", or "!~"
    If none of these are given, "=" will be used

    "=" does exact matching
    "~" does regex matching, supporting globs (*)
    "!" does inverse "=" matching
    "!~" does inverse "~" matching

    "~*.txt" matches all .txt files, for example
    
	$ dsglobus -ls -ep <endpoint> -p <path> --filter '~*.txt'  # all txt files
	$ dsglobus -ls -ep <endpoint> -p <path> --filter '!~file1.*'  # not starting in "file1."
	$ dsglobus -ls -ep <endpoint> -p <path> --filter '~*ile3.tx*'  # anything with "ile3.tx"
	$ dsglobus -ls -ep <endpoint> -p <path> --filter '=file2.txt'  # only "file2.txt"
	$ dsglobus -ls -ep <endpoint> -p <path> --filter 'file2.txt'  # same as '=file2.txt'
	$ dsglobus -ls -ep <endpoint> -p <path> --filter '!=file2.txt'  # anything but "file2.txt"

	"""
	
	client_id = MyGlobus['rda_quasar_client_id']
	tokens = get_tokens(client_id)
	transfer_refresh_token = tokens['transfer_rt']
	endpoint = get_endpoint_by_name(data['endpoint'])
	
	client = load_rda_native_client(client_id)
	tc_authorizer = RefreshTokenAuthorizer(transfer_refresh_token, client)
	tc = TransferClient(authorizer=tc_authorizer)

	ls_params = {"path": data['path']}
	if data['filter_pattern']:
		ls_params.update({"filter": "name:{}".format(data['filter_pattern'])})
	
	def cleaned_item_name(item):
		return item["name"] + ("/" if item["type"] == "dir" else "")
        
	fields=[
			("User", "user"),
			("Group", "group"),
			("Permissions", "permissions"),
			("Size", "size"),
			("Last Modified", "last_modified"),
			("File Type", "type"),
			("Filename", cleaned_item_name),
	]

	ls_response = tc.operation_ls(endpoint, **ls_params)
	print_table(ls_response, fields)
	
	return ls_response.data

#=========================================================================================
def read_json_from_stdin():
	"""Read arguments from stdin"""
	in_json=""
	for line in sys.stdin.readlines():
		in_json += line
	json_dict = json.loads(in_json)
	return json_dict

#=========================================================================================
def do_action(data):
	""" Run operations based on command line or JSON input """
	
	try:
		action = data['action']
	except KeyError:
		msg = "[do_action] 'action' missing from JSON or command-line input.  Run dsglobus -h for usage instructions."
		my_logger.error(msg)
		sys.exit(1)
	
	command = data['action']
	
	dispatch = {
			"ap": add_endpoint_acl_rule,
			"rp": delete_endpoint_acl_rule,
			"st": submit_dsrqst_transfer,
			"ls": list_endpoint_files,
			"transfer": submit_rda_transfer,
			"tb": submit_rda_transfer,
			"dr": submit_rda_transfer,
			"tb-quasar" : submit_rda_transfer,
			"dr-quasar" : submit_rda_transfer,
			"gt": get_task_info,
			"tl": task_list
	}
	if command in dispatch:
		command = dispatch[command]
	else:
		msg = "[do_action] command {} not found.".format(command)
		my_logger.error(msg)
		sys.exit(1)
	
	return command(data)

#=========================================================================================
def valid_date(date_str):
	""" Validate date input """
	from time import strptime
	fmt = "%Y-%m-%d"
	try:
		date_struct = strptime(date_str, fmt)
		return datetime(date_struct[0], date_struct[1], date_struct[2]).isoformat()
	except ValueError:
		msg = "Not a valid date: '{0}'.".format(date_str)
		raise argparse.ArgumentTypeError(msg)

#=========================================================================================
def parse_input():
	""" Parse command line arguments """
	import re
	from time import strptime
	
	desc = "Manage RDA Globus shared endpoints and endpoint permissions."	
	epilog = textwrap.dedent('''\
	Examples:
	  - Grant share permission to a user for dsrqst index 1234:
	        dsglobus -ap -ri 1234
	
	  - Delete permission from a user and delete the access share rule for dsrqst index 1234:
	        dsglobus -rp -ri 1234
	
	  - Share all files from RDA dataset ds131.2 with a user:
	        dsglobus -ap -ds 131.2 -em tcram@ucar.edu

	  - Transfer data from GLADE to the NCAR Quasar tape system
	        dsglobus --transfer --source-endpoint 'rda-glade' --destination-endpoint 'rda-quasar' --source-file /ds999.9/file.txt --destination-file /ds999.9/file.txt
	  			 
	  - List files on the 'NCAR RDA Quasar' endpoint:
	        dsglobus -ls -ep 'NCAR RDA Quasar' -p /ds999.9/cmorph_v1.0/2019

	Filtering:
	    When using the --filter option, you can list files and dirs on a specific path on an endpoint based on the filter criterion.
	    
        Filter patterns must start with "=", "~", "!", or "!~"
        If none of these are given, "=" will be used

        "=" does exact matching
        "~" does regex matching, supporting globs (*)
        "!" does inverse "=" matching
        "!~" does inverse "~" matching
	    
        "~*.txt" matches all .txt files, for example
	    
	    $ dsglobus -ls -ep <endpoint> -p <path> --filter '~*.txt'  # all txt files
	    $ dsglobus -ls -ep <endpoint> -p <path> --filter '!~file1.*'  # not starting in "file1."
	    $ dsglobus -ls -ep <endpoint> -p <path> --filter '~*ile3.tx*'  # anything with "ile3.tx"
	    $ dsglobus -ls -ep <endpoint> -p <path> --filter '=file2.txt'  # only "file2.txt"
	    $ dsglobus -ls -ep <endpoint> -p <path> --filter 'file2.txt'  # same as '=file2.txt'
	    $ dsglobus -ls -ep <endpoint> -p <path> --filter '!=file2.txt'  # anything but "file2.txt"
	''')
	
	date_fmt = "%Y-%m-%d"

	parser = argparse.ArgumentParser(prog='dsglobus', formatter_class=argparse.RawDescriptionHelpFormatter, description=desc, epilog=textwrap.dedent(epilog))

	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('--add-permission', '-ap', action="store_true", default=False, help='Add endpoint permission')
	group.add_argument('--remove-permission', '-rp', action="store_true", default=False, help='Delete endpoint permission')
	group.add_argument('--submit-transfer', '-st', action="store_true", default=False, help='Submit Globus transfer on behalf of user.  For dsrqst push transfers.')
	group.add_argument('--list-files', '-ls', action="store_true", default=False, help='List files on a specified endpoint path.')
	group.add_argument('--transfer', '-t', action="store_true", default=False, help='Transfer data between RDA endpoints.')
	group.add_argument('--get-task', '-gt', action="store_true", default=False, help='Show information about a Globus task.')
	group.add_argument('--task-list', '-tl', action="store_true", default=False, help='List Globus tasks for the current user.')
	
	parser.add_argument('--request-index', '-ri', action="store", dest="REQUESTINDEX", type=int, help='dsrqst request index')
	parser.add_argument('--dataset', '-ds', action="store", dest="DATASETID", help='Dataset ID.  Specify as dsnnn.n or nnn.n.  Required with the -em argument.')
	parser.add_argument('--email', '-em', action="store", dest="EMAIL", help='User e-mail.  Required with the -ds argument.')
	parser.add_argument('--no-email', '-ne', action="store_true", default=False, help='Do not send notification e-mail.  Default = False.')
	parser.add_argument('--endpoint', '-ep', action="store", dest="ENDPOINT", help='Endpoint ID or name.  Required with -ls argument.')
	parser.add_argument('--source-endpoint', '-se', action="store", dest="SOURCE_ENDPOINT", help='Source endpoint ID or name.  Required with --transfer option.')
	parser.add_argument('--destination-endpoint', '-de', action="store", dest="DESTINATION_ENDPOINT", help='Destination endpoint ID or name.  Required with --transfer.')
	parser.add_argument('--source-file', '-sf', action="store", dest="SOURCE_FILE", help='Path to source file name, relative to source endpoint host path.  Required with --transfer option.')
	parser.add_argument('--destination-file', '-df', action="store", dest="DESTINATION_FILE", help='Path to destination file name, relative to destination endpoint host path.  Required with --transfer.')
	parser.add_argument('--path', '-p', action="store", dest="PATH", help='Directory path on endpoint.  Required with -ls argument.')
	parser.add_argument('--filter', action="store", dest="FILTER_PATTERN", help='Filter applied to --list-files.')
	parser.add_argument('--task-id', action="store", dest="TASK_ID", help='Globus task ID.')
	parser.add_argument('--limit', action="store", dest="LIMIT", type=int, help='Limit number of results.')
	parser.add_argument('--filter-task-id', action="store", dest="FILTER_TASK_ID", help='task UUID to filter by.')
	parser.add_argument('--filter-type', action="store", dest="FILTER_TYPE", help='Filter results to only TRANSFER or DELETE tasks.', choices=['TRANSFER', 'DELETE'])
	parser.add_argument('--filter-status', action="store", dest="FILTER_STATUS", help='Filter results to given task status.', choices=['ACTIVE', 'INACTIVE', 'FAILED', 'SUCCEEDED'])
	parser.add_argument('--filter-requested-before', action="store", dest="FILTER_REQUESTED_BEFORE", help='Filter results to tasks submitted before given time.', type=valid_date)
	parser.add_argument('--filter-requested-after', action="store", dest="FILTER_REQUESTED_AFTER", help='Filter results to tasks submitted after given time.', type=valid_date)
	parser.add_argument('--filter-completed-before', action="store", dest="FILTER_COMPLETED_BEFORE", help='Filter results to tasks completed before given time.', type=valid_date)
	parser.add_argument('--filter-completed-after', action="store", dest="FILTER_COMPLETED_AFTER", help='Filter results to tasks completed after given time.', type=valid_date)
	
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)
	
	args = parser.parse_args(sys.argv[1:])
	my_logger.info("[parse_input] Input command & arguments: {0}: {1}".format(sys.argv[0], args))	

	opts = vars(args)
	if args.add_permission:
		opts.update({"action": "ap"})
	if args.remove_permission:
		opts.update({"action": "rp"})
	if args.submit_transfer:
		opts.update({"action": "st"})
	if args.list_files:
		opts.update({"action": "ls"})
	if args.transfer:
		opts.update({"action": "transfer"})
	if args.get_task:
		opts.update({"action": "gt"})
	if args.task_list:
		opts.update({"action": "tl"})
	
	if args.no_email:
		opts.update({'notify': False})
	else:
		opts.update({'notify': True})
	
	if args.get_task and args.TASK_ID is None:
		msg = "Option --get-task requires --task-id."
		my_logger.error(msg)
		parser.error(msg)
	if args.transfer and (args.SOURCE_ENDPOINT is None or args.DESTINATION_ENDPOINT is None or args.SOURCE_FILE is None or args.DESTINATION_FILE is None):
		msg = "Option --transfer requires arguments [--source-endpoint, --destination-endpoint, --source-file, --destination-file]."
		my_logger.error(msg)
		parser.error(msg)
	if args.list_files and (args.ENDPOINT is None or args.PATH is None):
		msg = "Option --list-files requires both --endpoint and --directory."
		my_logger.error(msg)
		parser.error(msg)
	if args.add_permission and (args.REQUESTINDEX and args.DATASETID):
		msg = "Please specify only the dsrqst index (-ri) or dataset ID (-ds), not both."
		my_logger.error(msg)
		parser.error(msg)
	if args.remove_permission and (args.REQUESTINDEX and args.DATASETID):
		msg = "Please specify only the dsrqst index (-ri) or dataset ID (-ds), not both."
		my_logger.error(msg)
		parser.error(msg)
	if args.submit_transfer and args.REQUESTINDEX is None:
		msg = "Option --submit-transfer requires dsrqst index (--request-index)."
		my_logger.error(msg)
		parser.error(msg)
	if args.DATASETID and args.EMAIL is None:
		msg = "Option dataset ID (--dataset) requires email (--email)."
		my_logger.error(msg)
		parser.error(msg)
	if args.EMAIL and args.DATASETID is None:
		msg = "Option email (--email) requires dataset ID (--dataset)."
		my_logger.error(msg)
		parser.error(msg)

	if args.REQUESTINDEX:
		opts.update({'ridx': args.REQUESTINDEX})
		opts.update({'type': 'dsrqst'})
	elif args.DATASETID:
		dsid = args.DATASETID
		if not re.match(r'^(ds){0,1}\d{3}\.\d{1}$', dsid, re.I):
			msg = "Please specify the dataset id as dsnnn.n or nnn.n"
			my_logger.error(msg)
			parser.error(msg)
		searchObj = re.search(r'^\d{3}\.\d{1}$', dsid)
		if searchObj:
			dsid = "ds%s" % dsid
		opts.update({'dsid': dsid.lower()})
		opts.update({'email': args.EMAIL})
		opts.update({'type': 'dataset'})
	elif args.list_files:
		pass
	elif args.transfer:
		opts.update({"files": [{"source_file": args.SOURCE_FILE, "destination_file": args.DESTINATION_FILE}]})
	elif args.get_task:
		pass
	elif args.task_list:
		pass
	else:
		parser.print_help()
		sys.exit(1)

	opts.update({'print': True})
	
	# convert all keys in opts to lower case
	opts = {k.lower(): v for k,v in opts.items()}

	return opts
	
#=========================================================================================
def configure_log(**kwargs):
	""" Set up log file """
	LOGPATH = '/glade/scratch/tcram/logs/globus'
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
	handler = logging.handlers.RotatingFileHandler(LOGPATH+'/'+LOGFILE,maxBytes=10000000,backupCount=5)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	my_logger.addHandler(handler)
	
	""" Console logger """
	console_logger.setLevel(logging.INFO)
	console = logging.StreamHandler()
	console.setFormatter(formatter)
	console_logger.addHandler(console)
	
	return

#=========================================================================================
def handle_error(err, **kwargs):
	if 'name' in kwargs:
		name = kwargs['name']
	else:
		name = ""
	
	msg = "{0} {1}".format(name, err)
	my_logger.error(msg, exc_info=True)
	
	if 'print_stdout' in kwargs and kwargs['print_stdout']:
		sys.exit(msg)
	
	return {'Error': msg}

#=========================================================================================
def iterable_response_to_dict(iterator):
	""" Convert Globus paginated/iterable response object to a dict """
	output_dict = {"DATA": []}
	for item in iterator:
		dat = item
		try:
			dat = item.data
		except AttributeError:
			pass
		output_dict["DATA"].append(dat)
	return output_dict

#=========================================================================================
def _key_to_keyfunc(k):
	"""
	We allow for 'keys' which are functions that map columns onto value
	types -- they may do formatting or inspect multiple values on the
	object. In order to support this, wrap string keys in a simple function
	that does the natural lookup operation, but return any functions we
	receive as they are.
	"""
	# if the key is a string, then the "keyfunc" is just a basic lookup
	# operation -- return that
	if isinstance(k, six.string_types):
		def lookup(x):
			return x[k]

		return lookup
	# otherwise, the key must be a function which is executed on the item
	# to produce a value -- return it verbatim
	return k

#=========================================================================================
def print_table(iterable, headers_and_keys, print_headers=True):
	# the iterable may not be safe to walk multiple times, so we must walk it
	# only once -- however, to let us write things naturally, convert it to a
	# list and we can assume it is safe to walk repeatedly

	iterable = list(iterable)

	# extract headers and keys as separate lists
	headers = [h for (h, k) in headers_and_keys]
	keys = [k for (h, k) in headers_and_keys]

	# convert all keys to keyfuncs
	keyfuncs = [_key_to_keyfunc(key) for key in keys]

	# use the iterable to find the max width of an element for each column, in
	# the same order as the headers_and_keys array
	# use a special function to handle empty iterable
	def get_max_colwidth(kf):
		def _safelen(x):
			try:
				return len(x)
			except TypeError:
				return len(str(x))

		lengths = [_safelen(kf(i)) for i in iterable]
		if not lengths:
			return 0
		else:
			return max(lengths)

	widths = [get_max_colwidth(kf) for kf in keyfuncs]
	# handle the case in which the column header is the widest thing
	widths = [max(w, len(h)) for w, h in zip(widths, headers)]

	# create a format string based on column widths
	format_str = " | ".join("{:" + str(w) + "}" for w in widths)

	def none_to_null(val):
		if val is None:
			return "NULL"
		return val

	# print headers
	if print_headers:
		print(format_str.format(*[h for h in headers]))
		print(format_str.format(*["-" * w for w in widths]))
	# print the rows of data
	for i in iterable:
		print(format_str.format(*[none_to_null(kf(i)) for kf in keyfuncs]))

#=========================================================================================
""" Set up logging """
my_logger = logging.getLogger(__name__)
console_logger = logging.getLogger('console')
configure_log(level='info')

if __name__ == "__main__":
	from_pipe = not os.isatty(sys.stdin.fileno())
	if from_pipe:
		json_input = read_json_from_stdin()
		main(json_input=json_input)
	else:
		main()
