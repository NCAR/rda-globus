#!/glade/u/apps/opt/python/2.7.7/gnu-westmere/4.8.2/bin/python
#
##################################################################################
#
#     Title : dsglobus.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 02/17/2017
#   Purpose : Python module to create and manage shared endpoints to facilitate
#             Globus data transfers from the RDA.
#
#             *** NOTE: Python 2.7 or later required ***
#
# Work File : $DSSHOME/lib/python/dsglobus.py*
# Test File : $DSSHOME/lib/python/dsglobus_test.py*
# Github    : https://github.com/NCAR/rda-globus/python/dsglobus.py
#
##################################################################################

import sys

""" Check Python version (2.7 or later required) """
try:
	assert sys.version_info >= (2, 7)
except AssertionError:
	print "Error: Python version 2.7 or later required."
	raise

sys.path.append("/glade/u/home/rdadata/lib/python")
sys.path.append("/glade/u/home/tcram/lib/python")

sys.path.append("/glade/u/apps/contrib/globus-sdk/1.1.0")

import argparse
import logging
import logging.handlers
import json
import textwrap
import re
from datetime import datetime
from time import strftime
from phpserialize import unserialize
try:
    from urllib.parse import urlencode
except:
    from urllib import urlencode

from MyLOG import show_usage
from PyDBI import myget, myupdt, myadd, mymget
from MyGlobus import headers, MyGlobus
from globus_sdk import (TransferClient, TransferAPIError, AccessTokenAuthorizer,
                        AuthClient, GlobusError, GlobusAPIError, NetworkError)
from globus_utils import load_app_client


def main():
	opts = parse_input()
	action = opts['action']
	
	if opts['removePermission']:
		result = delete_endpoint_acl_rule(action, opts)
	elif opts['addPermission']:
		result = add_endpoint_acl_rule(action, opts)
	elif opts['submitTransfer']:
		result = submit_dsrqst_transfer(opts)
	
	return result

def add_endpoint_acl_rule(action, data):
	""" Create a new endpoint access rule
	    action = 1: dsrqst share
	           = 2: standard dataset share
	"""
	if 'print' in data:
		print_stdout = data['print']
	else:
		print_stdout = False
	
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
			if myrqst['globus_rid']:
				msg = "[add_endpoint_acl_rule] Globus ACL rule has already been created for request {0}.".format(ridx)
				my_logger.info("msg")
				if 'print' in data and data['print']:
					sys.exit(msg)
				return {'access_id': myrqst['globus_rid'], 'share_url': myrqst['globus_url']}
			share_data = {'ridx': ridx}
			path = construct_share_path(1, share_data)
		except KeyError as err:
			return handle_error(err, name="[add_endpoint_acl_rule]", print_stdout=print_stdout)

	elif (action == 2):
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
			path = construct_share_path(2, share_data)
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
		print msg
	my_logger.info("[add_endpoint_acl_rule] {0}".format(msg))
	my_logger.info("[add_endpoint_acl_rule] User email: {0}".format(email))
	
	if 'print' in data and data['print']:
		share_data.update({'print': True})
	
	url = construct_share_url(action, share_data)
	share_data.update({'globus_rid': result['access_id'],'globus_url': url})	
	update_share_record(action, share_data)
	
	return {'access_id': result["access_id"], 'share_url': url}

def delete_endpoint_acl_rule(action, data):
	""" Delete a specific endpoint access rule
	    action = 1: dsrqst share
	           = 2: standard dataset share
	""" 
	if 'print' in data:
		print_stdout = data['print']
	else:
		print_stdout = False

	if (action == 1):
		try:
			endpoint_id = MyGlobus['data_request_ep']
			ridx = data['ridx']
			cond = " WHERE rindex='{0}'".format(ridx)
			myrqst = myget('dsrqst', ['*'], cond)
			if (len(myrqst) == 0):
				msg = "[delete_endpoint_acl_rule] Request index not on file"
				if 'print' in data and data['print']:
					sys.exit("Error: {0}".format(msg))
				my_logger.warning(msg)
				return {'Error': msg}
			if not myrqst['globus_rid']:
				msg = "[delete_endpoint_acl_rule] Globus ACL rule not found in request record (request index {0}).".format(ridx)
				if 'print' in data and data['print']:
					sys.exit("Error: {0}".format(msg))
				my_logger.warning(msg)
				return {'Error': msg}
			else:
				rule_id = myrqst['globus_rid']
				record = []
				record.append({unicode('globus_rid'): None,
				               unicode('globus_url'): None
				               })
				myupdt('dsrqst', record[0], cond)
		except KeyError as err:
			return handle_error(err, name="[delete_endpoint_acl_rule]", print_stdout=print_stdout)

	elif (action == 2):
		try:
			endpoint_id = MyGlobus['datashare_ep']
			email = data['email']
			dsid = data['dsid']
			cond = " WHERE email='{0}' AND dsid='{1}' AND status='ACTIVE'".format(email, dsid)
			myshare = myget('goshare', ['*'], cond)
			if (len(myshare) == 0):
				msg = "[delete_endpoint_acl_rule] Globus share record not found for e-mail = {0} and dsid = {1}.".format(email, dsid)
				if 'print' in data and data['print']:
					sys.exit("Error: {0}".format(msg))
				my_logger.warning(msg)
				return {'Error': msg}
			if not myshare['globus_rid']:
				msg = "[delete_endpoint_acl_rule] Globus ACL rule not found in Globus share record (e-mail: {0}, dsid: {1}).".format(email, dsid)
				if 'print' in data and data['print']:
					sys.exit("Error: {0}".format(msg))
				my_logger.warning(msg)
				return {'Error': msg}
			else:
				rule_id = myshare['globus_rid']
				record = []
				record.append({unicode('delete_date'): datetime.now().strftime("%Y-%m-%d"),
				               unicode('status'): 'DELETED'
				               })
				myupdt('goshare', record[0], cond)
		except KeyError as err:
			return handle_error(err, name="[delete_endpoint_acl_rule]", print_stdout=print_stdout)

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
	if 'print' in data and data['print']:
		print msg
	my_logger.info("[delete_endpoint_acl_rule] {0}".format(msg))
	
	return msg

def submit_dsrqst_transfer(data):
	""" Submit a Globus transfer on behalf of the user.  For dsrqst 'push' transfers. """

	""" Get session ID from dsrqst record """
	ridx = data['ridx']
	cond = " WHERE rindex={0}".format(ridx)
	myrqst = myget('dsrqst', ['*'], cond)
	if (len(myrqst) == 0):
		msg = "[submit_dsrqst_transfer] Request index not found in DB"
		my_logger.warning(msg)
		sys.exit(1)

	session = get_session(myrqst['session_id'])
	email = session['email']
	dsid = session['dsid']
	
	# Get request files from wfrqst
	files = mymget('wfrqst', ['wfile'], cond)
	if (len(files) > 0):
		selected = {}
		for i in range(len(files)):
			selected.update({i: files[i]['wfile']})
	else:
		return null

	""" Define source endpoint ID and paths """
	host_endpoint = MyGlobus['host_endpoint_id']
	source_endpoint_id = MyGlobus['data_request_ep']
	destination_endpoint_id = session['endpoint_id']

	""" Check if user has a share set up for this endpoint & path """
	share_data = {'ridx': ridx, 'notify': True}
	if not query_acl_rule(1, share_data):
		data = add_endpoint_acl_rule(1, share_data)
	directory = construct_share_path(1, share_data)

	""" Instantiate the Globus SDK transfer client """
	transfer = TransferClient(authorizer=RefreshTokenAuthorizer(
		session['transfer.api.globus.org']['refresh_token'], load_app_client()))
        
	""" Instantiate TransferData object """
	transfer_data = TransferData(transfer_client=transfer,
								 source_endpoint=source_endpoint_id,
								 destination_endpoint=destination_endpoint_id,
								 label=session['label'])

	""" Add files to be transferred.  Note source_path is relative to the source
		endpoint base path. """
	for file in selected:
		source_path = directory + selected[file]
		dest_path = session['dest_path'] + selected[file]
		transfer_data.add_item(source_path, dest_path)

	transfer.endpoint_autoactivate(source_endpoint_id)
	transfer.endpoint_autoactivate(destination_endpoint_id)
	task_id = transfer.submit_transfer(transfer_data)['task_id']

	""" Store task_id in request record """
	record = [{unicode('task_id'): task_id}]
	myupdt('dsrqst', record[0], cond)

	"""	Create share record in goshare """

	return task_id

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
	
def get_user_id(identity):
	""" Get the UUID assigned by Globus Auth. Input argument 'identity' can be one of
	    the following:
	    
	    GlobusID (Globus primary identity): in the form of user@globusid.org
		NCAR RDA identity                 : in the form of user@domain.com@rda.ucar.edu, where user@domain.com is the user's RDA e-mail login
		E-mail identity                   : in the form of user@domain.com
	"""
	try:
		ac = AuthClient(authorizer=AccessTokenAuthorizer(MyGlobus['auth_token']))
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

def query_acl_rule(action, data):
	""" Check if an active ACL rule exists for a given RDA user
	    action = 1: dsrqst share
	           = 2: standard dataset share
	"""
	if 'print' in data:
		print_stdout = data['print']
	else:
		print_stdout = False
	
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
	""" Update the user's Globus share in RDADB
	    action = 1: dsrqst share
	           = 2: standard dataset share
	"""
	try:
		globus_rid = data['globus_rid']
		globus_url = data['globus_url']
	except KeyError as err:
		return handle_error(err, name="[update_share_record]", print_stdout=print_stdout)
	
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
			return handle_error(err, name="[update_share_record]", print_stdout=print_stdout) 
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
			return handle_error(err, name="[update_share_record]", print_stdout=print_stdout)

	return
	
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

def parse_input():
	""" Parse command line arguments """
	desc = "Manage RDA Globus shared endpoints and endpoint permissions."	
	epilog = textwrap.dedent('''\
	Examples:
	  - Grant share permission to a user for dsrqst index 1234:
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
	group.add_argument('-st', action="store_true", default=False, help='Submit Globus transfer on behalf of user.  For dsrqst push transfers.')

	parser.add_argument('-ri', action="store", dest="REQUESTINDEX", type=int, help='dsrqst request index')
	parser.add_argument('-ds', action="store", dest="DATASETID", help='Dataset ID.  Specify as dsnnn.n or nnn.n.  Required with the -em argument.')
	parser.add_argument('-em', action="store", dest="EMAIL", help='User e-mail.  Required with the -ds argument.')
	parser.add_argument('-ne', action="store_true", default=False, help='Do not send notification e-mail.  Default = False.')
	
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)
	
	args = parser.parse_args(sys.argv[1:])
	my_logger.info("{0}: {1}".format(sys.argv[0], args))
	
	opts = vars(args)
	opts['addPermission'] = opts.pop('ap')
	opts['removePermission'] = opts.pop('rp')
	opts['submitTransfer'] = opts.pop('st')
	
	if opts['ne']:
		opts['notify'] = False
	else:
		opts['notify'] = True
	opts.pop('ne')
	
	if (opts['REQUESTINDEX'] and opts['DATASETID']):
		msg = "Please specify only the dsrqst index (-ri) or dataset ID (-ds), not both."
		my_logger.error(msg)
		sys.exit(msg)
	if (opts['submitTransfer'] and not opts['REQUESTINDEX']):
		msg = "Please specify the dsrqst index (-ri) with the -st flag."
		my_logger.error(msg)
		sys.exit(msg)
	if opts['REQUESTINDEX']:
		opts['ridx'] = opts.pop('REQUESTINDEX')
		opts.update({'action': 1})
	elif opts['DATASETID']:
		if not opts['EMAIL']:
			msg = "The e-mail option (-em) is required with the dataset ID option (-ds)."
			my_logger.error(msg)
			sys.exit(msg)
		dsid = opts['DATASETID']
		if not re.match(r'^(ds){0,1}\d{3}\.\d{1}$', dsid, re.I):
			msg = "Please specify the dataset id as dsnnn.n or nnn.n"
			my_logger.error(msg)
			sys.exit(msg)
		searchObj = re.search(r'^\d{3}\.\d{1}$', dsid)
		if searchObj:
			opts['DATASETID'] = "ds%s" % dsid
		opts['dsid'] = opts.pop('DATASETID').lower()
		opts['email'] = opts.pop('EMAIL')
		opts.update({'action': 2})
	elif opts['EMAIL']:
		msg = "The dataset ID option (-ds) is required with the e-mail option (-em)."
		my_logger.error(msg)
		sys.exit(msg)
	else:
		parser.print_help()
		sys.exit(1)

	opts['print'] = True
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
		name = kwargs['name']
	else:
		name = ""
	
	msg = "{0} {1}".format(name, err)
	my_logger.error(msg, exc_info=True)
	
	if 'print_stdout' in kwargs and kwargs['print_stdout']:
		sys.exit(msg)
	
	return {'Error': msg}

#=========================================================================================
""" Set up logging """
my_logger = logging.getLogger(__name__)
configure_log(level='info')

if __name__ == "__main__":
    main()