#!/usr/bin/env python3

"""
     Title : retrieve_globus_metrics.py
    Author : Thomas Cram, tcram@ucar.edu
      Date : 02/04/2015
   Purpose : Python script to retrieve Globus data transfer metrics for RDA users.

 Work File : $DSSHOME/bin/retrieve_globus_metrics.py*
 Test File : $DSSHOME/bin/retrieve_globus_metrics_test.py*
 Github    : https://github.com/NCAR/rda-globus/blob/main/src/python/retrieve_globus_metrics.py
"""

import sys
import socket, re
import traceback

path1 = "/glade/u/home/rdadata/lib/python"
path2 = "/glade/u/home/tcram/lib/python"
if (path1 not in sys.path):
	sys.path.append(path1)
if (path2 not in sys.path):
	sys.path.append(path2)

from MyGlobus import MyGlobus, MyEndpoints, LOGPATH
from PgDBI import pgget, pgmget, pgadd, pgupdt
from PgLOG import *
from PgDBI import build_customized_email, add_yearly_allusage, check_wuser_wuid

from globus_utils import load_app_client
from globus_sdk import (TransferClient, AuthClient, RefreshTokenAuthorizer,
                        GlobusError, GlobusAPIError, NetworkError)

from datetime import datetime
import pytz
import logging
import logging.handlers

# Task list keys to retain
task_keys = ['status','bytes_transferred','task_id','owner_string',\
	     'owner_id', 'type','request_time','completion_time','files',\
	     'files_skipped','bytes_transferred',\
	     'source_endpoint_id', 'source_endpoint_display_name', \
	     'destination_endpoint_id']

# Keys for individual Globus task IDs
transfer_keys = ['destination_path','source_path', 'data_type']

# Endpoint UUIDs
endpoint_id_data_request = MyEndpoints['rda#data_request']
endpoint_id_datashare = MyEndpoints['rda#datashare']
endpoint_id_stratus = MyEndpoints['rda#stratus']

#=========================================================================================
def main(filters):

	# Get Globus transfer tasks
	my_logger.debug(__name__+': Getting tasks')
	transfer_tasks = get_tasks(filters)
	if doprint: print_doc(transfer_tasks, task_keys)
	my_logger.debug(__name__+': Adding/updating tasks in RDA DB')
	if len(transfer_tasks) > 0:
		add_tasks('gotask', transfer_tasks)

		# Get list of successful transfers for each Globus task id.
		if not task_only:
			my_logger.debug(__name__+': Getting and adding Globus transfers')
			endpoint_id = filters['filter_endpoint']
			for i in range(len(transfer_tasks)):
				task_id = transfer_tasks[i]['task_id']
				bytes = transfer_tasks[i]['bytes_transferred']
				my_logger.debug(__name__+': task_id: '+task_id)
				data_transfers = get_successful_transfers(task_id)
				if (len(data_transfers) > 0):
					add_successful_transfers('gofile', data_transfers, task_id, bytes, endpoint_id)
				else:
					msg = "[main] Warning: No successful transfers found for task ID {}.".format(task_id)
					my_logger.warning(msg)
					email_logmsg(msg)
				# Update usage from rda#datashare and rda#stratus endpoints into table allusage
				if (endpoint_id == endpoint_id_datashare or endpoint_id == endpoint_id_stratus):
					update_allusage(task_id)
	else:
		msg = "No transfer tasks found for endpoint {} and date range {}".format(filters['filter_endpoint'], filters['filter_completion_time'])
		my_logger.info(msg)

	my_logger.debug(__name__+': END')

#=========================================================================================
def get_tasks(filters):
	""" Get list of successful transfer tasks from the Globus transfer client """
	try:
		tasks = []
		tc_authorizer = RefreshTokenAuthorizer(MyGlobus['transfer_refresh_token'], load_app_client())
		tc = TransferClient(authorizer=tc_authorizer)
		for task in tc.paginated.endpoint_manager_task_list(**filters).items():
			tasks.append(task)
	except GlobusAPIError as e:
		msg = ("[get_tasks] Globus API Error\n"
		       "HTTP status: {}\n"
		       "Error code: {}\n"
		       "Error message: {}").format(e.http_status, e.code, e.message)
		my_logger.error(msg)
		email_logmsg(msg)
		raise e
	except NetworkError as e:
		msg = ("[get_tasks] Network Error\n"
			   "HTTP status: {}\n"
		       "Error code: {}\n"
		       "Error message: {}").format(e.http_status, e.code, e.message)
		my_logger.error(msg)
		email_logmsg(msg)
		raise e
	except GlobusError as e:
		msg = ("[get_tasks] Globus Error\n"
		       "Error message: {}").format(e.message)
		my_logger.exception(msg)
		email_logmsg(msg)
		raise e

	return tasks
	
#=========================================================================================
def add_tasks(go_table, data):
	""" Insert/update Globus transfer tasks in RDADB """
	
	# Prepare database records
	if (len(data) >= 1):
		records = create_recs(data, task_keys)
		records = map_endpoint_names(records)
		emails = get_globus_email(data)
		records = update_records(records, emails)
	else:
		msg = "[add_tasks] There are no transfer tasks in 'data'."
		my_logger.warning(msg)
		email_logmsg(msg)
		sys.exit()
	
	# Check if record already exists for each task id. Update if necessary.
	count_add = 0
	count_updt = 0
	task_keys.append('email')

	# task key 'owner_string' = field 'username' in gotask table.  Change task_keys accordingly.
	task_keys.append('username')
	task_keys.remove('owner_string')
	task_keys_str = ", ".join(task_keys)

	for i in range(len(records)):
		rec = records[i]

		# change record key 'owner_string' to 'username'
		rec['username'] = rec.pop('owner_string')

		condition = "task_id='{0}'".format(rec['task_id'])
		myrec = pgget(go_table, task_keys_str, condition)
		if (len(myrec) > 0):
			try:
				myrec['request_time'] = myrec['request_time'].replace(tzinfo=pytz.utc).isoformat()
				myrec['completion_time'] = myrec['completion_time'].replace(tzinfo=pytz.utc).isoformat()
			except KeyError:
				pass
			if not (rec == myrec):
				rec['request_time'] = rec['request_time'][:19]
				rec['completion_time'] = rec['completion_time'][:19]
				pgupdt(go_table, rec, condition)
				count_updt+=1
			else:
				my_logger.info("[add_tasks] DB record for task ID {0} exists and is up to date.".format(rec['task_id']))
		else:
			rec['request_time'] = rec['request_time'][:19]
			rec['completion_time'] = rec['completion_time'][:19]
			pgadd(go_table, rec)
			count_add+=1

	msg = "[add_tasks] {0} new transfer tasks added and {1} transfer tasks updated in table {2}".format(count_add, count_updt, go_table)
	my_logger.info(msg)
	email_logmsg(msg)
		
	if (count_add == 0):
		msg = "[add_tasks] No new Globus transfer tasks found."
		my_logger.warning(msg)
		email_logmsg(msg)
		
	return

#=========================================================================================
def get_successful_transfers(task_id):
	""" Get list of files transferred successfully from the Globus transfer client """

	try:
		transfers = []
		tc_authorizer = RefreshTokenAuthorizer(MyGlobus['transfer_refresh_token'], load_app_client())
		tc = TransferClient(authorizer=tc_authorizer)
		for transfer in tc.paginated.endpoint_manager_task_successful_transfers(task_id).items():
			transfers.append(transfer)
	except GlobusAPIError as e:
		msg = ("[get_successful_transfers] Globus API Error\n"
		       "HTTP status: {}\n"
		       "Error code: {}\n"
		       "Error message: {}").format(e.http_status, e.code, e.message)
		my_logger.error(msg)
		email_logmsg(msg)
		raise e
	except NetworkError as e:
		msg = ("[get_successful_transfers] Network Error\n"
			   "HTTP status: {}\n"
		       "Error code: {}\n"
		       "Error message: {}").format(e.http_status, e.code, e.message)
		my_logger.error(msg)
		email_logmsg(msg)
		raise e
	except GlobusError as e:
		msg = ("[get_successful_transfers] Globus Error\n"
		       "Error message: {}").format(e.message)
		my_logger.exception(msg)
		email_logmsg(msg)
		raise e

	# return all successful transfers
	return transfers

#=========================================================================================
def handle_error(r, data):
	""" Handle errors returned by API resource

	Example:
	   Verify that task id exists.  Response will be as follows if not:
	   r.status_code = 404
	   r.headers['x-transfer-api-error'] = 'TaskNotFound'
	   data['code'] = 'TaskNotFound'
	   data['message'] = 'Task ID <task_id> not found'
	   data['resource'] = '/endpoint_manager/task/<task_id>/successful_transfers'

	   Also, for failed tasks, the task ID will exist, but response will have zero content:
	   len(data['DATA']) = 0
	"""

	msg = "Error {0}: {1}".format(str(r.status_code), data['message'])
	msg += " Resource: {0}".format(data['resource'])
	my_logger.error(msg)
	error_code = r.headers['x-transfer-api-error']
	
	if (error_code == 'EndpointNotFound' or error_code == 'ServiceUnavailable'):
		sys.exit()
	else:
		return
	
#=========================================================================================
def prepare_transfer_recs(data, task_id, bytes, endpoint):
	""" Parse file names in data_transfers dictionary """

	try:
		from urllib.parse import unquote
	except:
		from urllib import unquote
	
	transfer_recs = []
	
	for i in range(len(data)):
		destination_path = data[i]['destination_path']
		source_path = data[i]['source_path']
		data_type = data[i]['DATA_TYPE']
		pathsplit = source_path.split("/")

		if (endpoint == endpoint_id_datashare or endpoint == endpoint_id_stratus):
			# Query file size from wfile.data_size
		    
			# Get dsid from source_path
			a = re.search(r'/ds\d{3}\.\d{1}/', source_path)
			if a:
				b = re.search(r'ds\d{3}\.\d{1}', a.group())
			else:
				msg = "[prepare_transfer_recs] Dataset ID not found"
				my_logger.warning(msg)
				return transfer_recs
		    
			try:
				dsid = b.group()
			except AttributeError as attr_err:
				msg = "[prepare_transfer_recs] {}".format(attr_err)
				my_logger.warning(msg)
				msg = "[prepare_transfer_recs] source_path: {}".format(source_path)
				my_logger.info(msg)
				return transfer_recs

			# Get transferred file name
			c = re.split(a.group(), source_path)
			if c:
				tfile = unquote(c[1])
			else:
				msg = "[prepare_transfer_recs] transfer file not found"
				my_logger.warning(msg)
				msg = "[prepare_transfer_recs] source_path: {}".format(source_path)
				my_logger.info(msg)
				return transfer_recs
			
			field = 'wfile'
			table = 'wfile'			
			condition = "dsid='{0}' AND {1}='{2}'".format(dsid, field, tfile)
			myrec = pgget(table, 'data_size', condition)
			
			if (len(myrec) > 0):
				transfer_recs.append({
				             'destination_path':destination_path,
				             'source_path':source_path,
				             'data_type':data_type,
				             'task_id':task_id,
			                 'file_name': unquote(pathsplit[-1]),
			                 'rindex':None,
			                 'dsid':dsid,
			                 'size':myrec['data_size'],
			                 'count':1})
		
		# rda#data_request
		if (endpoint == endpoint_id_data_request):
			# Get request ID from source_path
			a = re.search(r'/[A-Z]+\d+/', source_path)
			if a:
				b = re.search(r'\d+', a.group(0))
			else:
				msg = "[prepare_transfer_recs] Request ID not found"
				my_logger.warning(msg)
				return transfer_recs
			
			try:
				rindex = int(b.group())
			except AttributeError as attr_err:
				msg = "[prepare_transfer_recs] {}".format(attr_err)
				my_logger.warning(msg)
				msg = "[prepare_transfer_recs] source_path: {}".format(source_path)
				my_logger.info(msg)
				return transfer_recs

			condition = "rindex='{0}'".format(rindex)
			myrec = pgget('dsrqst', 'dsid', condition)
			if (len(myrec) == 0):
				myrec = pgget('dspurge', 'dsid', condition)
			if (len(myrec) > 0):
				dsid = myrec['dsid']
			else:
				my_logger.warning("Request index {0} not found".format(rindex))
				dsid = None
			
			transfer_recs.append({
				         'destination_path':destination_path,
				         'source_path':source_path,
				         'data_type':data_type,
			             'task_id':task_id,
			             'file_name':pathsplit[-1],
			             'rindex':rindex,
			             'dsid':dsid,
			             'size':bytes,
			             'count':None})
	
	return transfer_recs

#=========================================================================================
# Insert/update list of files transferred successfully

def add_successful_transfers(go_table, data, task_id, bytes, endpoint):
	""" Insert/update list of files transferred successfully """

	my_logger.info("[add_successful_transfers] Adding successful transfers for task_id: {0}".format(task_id))
	
	count_add = 0
	count_updt = 0
	count_none = 0

	# Prepare database records
	if (len(data) >= 1):
		records = prepare_transfer_recs(data, task_id, bytes, endpoint)
		if (len(records) == 0):
			msg = "[add_successful_transfers] Task ID {}: transfer_recs is empty".format(task_id)
			my_logger.warning(msg)
			email_logmsg(msg)				
			return
	else:
		my_logger.warning("[add_successful_transfers] There are no successful transfers in the return document.")
		return
	
	# Check if record already exists. Update if necessary.
	keys = transfer_keys
	keys.extend(['task_id','file_name','rindex','dsid','size','count'])
	keys_str = ",".join(keys)
	
	dsrqst_count = 0
	
	# Skip files named index.html, .htaccess, *.email_notice, *.csh, *.pl
	for i in range(len(records)):
		searchObj = re.search(r'(index\.html)$|(htaccess)$|(\.email_notice)$|(\.csh)$', records[i]['source_path'])
		if searchObj:
			continue
		else:
			if (endpoint == endpoint_id_datashare or endpoint == endpoint_id_stratus):
				condition = "task_id='{0}' AND source_path='{1}'".format(records[i]['task_id'], records[i]['source_path'])
				myrec = pgget(go_table, keys_str, condition)
				if (len(myrec) > 0):
					if not (records[i] == myrec):
						pgupdt(go_table, records[i], condition)
						count_updt += 1
					else:
						count_none += 1
				else:
					pgadd(go_table, records[i])
					count_add += 1
			elif (endpoint == endpoint_id_data_request):
				dsrqst_count += 1
			else:
				my_logger.warning('[add_successful_transfers] Endpoint {0} not found'.format(endpoint))
				return

	if (endpoint == endpoint_id_data_request and len(records) > 0):
		dsrqst_rec = []
		pathsplit = records[0]['source_path'].split("/")
		file_name = pathsplit.pop()
		source_path = "/".join(pathsplit)
		dsrqst_rec.append({'task_id': task_id,
		                   'data_type': records[0]['DATA_TYPE'],
		                   'destination_path': records[0]['destination_path'],
		                   'source_path': source_path,
		                   'file_name': records[0]['file_name'],
		                   'rindex': records[0]['rindex'],
		                   'dsid': records[0]['dsid'],
		                   'size': bytes,
		                   'count': dsrqst_count
		                   })
		condition = "task_id='{0}' AND rindex={1}".format(task_id, dsrqst_rec[0]['rindex'])
		myrec = pgget(go_table, keys_str, condition)
		if (len(myrec) > 0):
			if not (dsrqst_rec == myrec):
				pgupdt(go_table, dsrqst_rec[0], condition)
				count_updt += 1
			else:
				count_none += 1
		else:
			pgadd(go_table, dsrqst_rec[0])
			count_add += 1
	
	msg_add_updt = "[add_successful_transfers] Task ID {0}: {1} transfers added and {2} transfers updated".format(task_id, count_add, count_updt)
	my_logger.info(msg_add_updt)
	email_logmsg(msg_add_updt)
	
	if (count_none > 0):
		msg_none = "[add_successful_transfers] Task ID {0}: {1} transfers already up to date".format(task_id, count_none)
		my_logger.info(msg_none)
		email_logmsg(msg_none)
	
#=========================================================================================
def update_allusage(task_id):
	""" Insert/update usage in dssdb.allusage_<yyyy> """

	from time import strftime
	method = 'GLOB'
	source = 'G'
	all_recs = []
	count_add = 0
	count_updt = 0
	
	condition = "task_id='{0}'".format(task_id)
	myrec = pgget('gotask', 'email, completion_time, bytes_transferred, EXTRACT(QUARTER FROM completion_time) AS quarter', condition)
	if (len(myrec) > 0):
		email = myrec['email']
		completion_time = myrec['completion_time']
		bytes_transferred = myrec['bytes_transferred']
		quarter = int(myrec['quarter'])
	else:
		my_logger.warning("[update_allusage] Task ID {0} not found in dssdb.gotask.".format(task_id))
		return
	
	# Format date and time.
	completion_date = myrec['completion_time'].strftime("%Y-%m-%d")
	completion_time = myrec['completion_time'].strftime("%H:%M:%S")
	completion_year = myrec['completion_time'].strftime("%Y")
	
	# Get user org_type and country
	wuid = check_wuser_wuid(email)
	if not wuid:
		my_logger.info("wuid not found for email {}".format(email))
		org_type = None
		country = None
	else:
		condition = "wuid={}".format(wuid)
		myrec = pgget('wuser', 'org_type, country', condition)
		if (len(myrec) > 0):
			org_type = myrec['org_type']
			country = myrec['country']
		else:
			my_logger.info("wuser not found for email {}, task_id {}.".format(email, task_id))
			org_type = None
			country = None
	
	task_record = {
		'email': email,
		'org_type': org_type,
		'country': country,
		'date': completion_date,
		'time': completion_time,
		'quarter': quarter,
		'method': method,
		'source': source,
		'midx': 0,
		'ip': None
	}

	# Get dsid and calculate size.  Query table gofile and handle multiple records, if
	# necessary.
	condition = "task_id='{0}' GROUP BY dsid".format(task_id)
	myrecs = pgmget('gofile','dsid, SUM(size) as sum', condition)

	if myrecs:
		# convert myrecs from a dictionary of lists into a list of dictionaries
		myrecs = [dict(zip(myrecs, vals)) for vals in zip(*myrecs.values())]

		for i in range(len(myrecs)):
			dsid = myrecs[i]['dsid']
			size = int(myrecs[i]['sum'])
			usage_record = {'dsid': dsid, 'size': size}
			usage_record.update(task_record)
			all_recs.append(usage_record)
	else:
		my_logger.info("[update_allusage] Task ID {0} not found in table gofile. Adding/updating record in allusage with dsid=ds000.0".format(task_id))
		usage_record = {'dsid': 'ds000.0', 'size': bytes_transferred}
		usage_record.update(task_record)
		all_recs.append(usage_record)

	for i in range(len(all_recs)):
		# check if record already exists in allusage table (dsid, date, time, and size will match)
		table = "allusage_{}".format(completion_year)
		fields = ['aidx', 'email']
		fields_str = ",".join(fields)
		dsid = all_recs[i]['dsid']
		date = all_recs[i]['date']
		time = all_recs[i]['time']
		size = all_recs[i]['size']
		email = all_recs[i]['email']
		cond = "dsid='{0}' AND date='{1}' AND time='{2}' AND size={3} AND method='{4}'".format(dsid, date, time, size, method)
		myrec = pgget(table, fields_str, cond)

		if (len(myrec) > 0):
			if not email or (email == myrec['email']):
				# Globus user email is undefined, or email matches email in allusage record.  Skip.
				continue
			else:
				# update email with allusage record
				cond = "aidx={}".format(myrec['aidx'])
				pgupdt(table, all_recs[i], cond)
				count_updt += 1
		else:
			# Add new record to allusage table
			try:
				count_add += add_yearly_allusage(completion_year, all_recs[i], docheck=4)
			except Exception as e:
				msg = "[update_allusage] Error adding/updating allusage record.\n{}".format(traceback.format_exc(e))
				my_logger.error(msg)
				email_logmsg(msg)

	msg = "[update_allusage] Task ID {0}: {1}/{2} metrics added/updated in allusage table.".format(task_id, count_add, count_updt)
	my_logger.info(msg)
	email_logmsg(msg)
	
#=========================================================================================
def format_date(date_str, fmt):
	""" Convert date string into ISO 8601 format (YYYY-MM-DDTHH:MM:ss) """

	from time import strptime
	
	date = strptime(date_str, fmt)
	isodate = datetime(date[0], date[1], date[2]).isoformat()
	
	return isodate

#=========================================================================================
def create_recs(data, keys):
	""" Create a list of dictionaries (records) from the Globus task document output,
	    to be inserted into RDADB """

	records = []
	go_dict = {}
	for i in range(len(data)):
		for key in data[i]:
			if key in keys:
				go_dict[key] = data[i][key]
			else:
				continue
		records.append(go_dict)
		go_dict = {}
	return records
	
#=========================================================================================
def map_endpoint_names(data):
	""" Map source endpoint ID to legacy canonical endpoint name """

	for i in range(len(data)):
		source_endpoint_id = data[i]['source_endpoint_id']
		if source_endpoint_id == MyEndpoints['rda#datashare']:
			data[i]['source_endpoint'] = 'rda#datashare'
		if source_endpoint_id == MyEndpoints['rda#stratus']:
			data[i]['source_endpoint'] = 'rda#stratus'
		if source_endpoint_id == MyEndpoints['rda#data_request']:
			data[i]['source_endpoint'] = 'rda#data_request'
	return data

#=========================================================================================
def get_globus_email(data):
	""" Get user's email address associated with their Globus account """

	emails = []
	rda_oidc = '@oidc.rda.ucar.edu'

	for i in range(len(data)):
		try:
			ac_authorizer = RefreshTokenAuthorizer(MyGlobus['auth_refresh_token'], load_app_client())
			ac = AuthClient(authorizer=ac_authorizer)
			owner_id = data[i]['owner_id']
			result = ac.get_identities(ids=owner_id)
			# check for RDA identity
			username = result.data['identities'][0]['username']
			if username.find(rda_oidc) > 0:
				email = username.replace(rda_oidc,'')
				my_logger.info("NCAR RDA identity found.  User email updated to {}".format(email))
			else:
				email = result.data['identities'][0]['email']
		except GlobusAPIError as e:
			msg = ("[get_globus_email] Globus API Error\n"
		       	   "HTTP status: {}\n"
		           "Error code: {}\n"
		           "Error message: {}").format(e.http_status, e.code, e.message)
			my_logger.error(msg)
			email_logmsg(msg)
			raise e
		except NetworkError as e:
			msg = ("[get_globus_email] Network Error\n"
			       "HTTP status: {}\n"
		           "Error code: {}\n"
		           "Error message: {}").format(e.http_status, e.code, e.message)
			my_logger.error(msg)
			email_logmsg(msg)
			raise e
		except GlobusError as e:
			msg = ("[get_globus_email] Globus Error\n"
		           "Error message: {}").format(e.message)
			my_logger.exception(msg)
			email_logmsg(msg)
			raise e

		if 'email':
			emails.append({'email': email})
		else:
			emails.append({'email':None})

	return emails
	
#=========================================================================================
def check_email(data):
	""" Check for user's email address in the dssdb.gouser table.  Add to records 
	    dictionary if found. """

	emails = []
	for i in range(len(data)):
		condition = " WHERE username='{0}' AND status='ACTIVE'".format(data[i]['owner_id'])
		myrec = myget('gouser', ['email'], condition)
		if 'email' in myrec:
			emails.append(myrec)
		else:
			emails.append({'email':None})
	return emails
	
#=========================================================================================
def update_records(list1,list2):
	""" Update the records list of task dictionaries """

	if (len(list1) != len(list2)):
		my_logger.warning("[update_records] Mismatch between len list1 ({0}) and len list2 ({1})".format(len(list1),len(list2)))
		return

	for i in range(len(list1)):
		list1[i].update(list2[i])
	return list1
	
#=========================================================================================
def print_doc(data, keys):
	""" Print output from the 'DATA' task document """
	for i in range(len(data)):
		print()
		for key in data[i]:
			if key in keys:
				print (key, '\t', data[i][key])
			else:
				continue

#=========================================================================================
def email_logmsg(msg):
	""" Send log message in email """

	try:
		if (PGLOG['DSCHECK']['cindex']):
			PGLOG['EMLMSG'] += "{0}\n".format(msg)
			subject = "Log from {}".format(get_command())
			cond = "cindex = {}".format(PGLOG['DSCHECK']['cindex'])
			build_customized_email('dscheck', 'einfo', cond, subject)
	except TypeError:
		pass		

#=========================================================================================
def set_filters(args):
	""" Set filters to pass to Globus transfer client """

	my_logger.debug('[set_filters] Defining Globus API filters')
	filters = {}
	filters['filter_status'] = 'SUCCEEDED'
	if (args['endpointID']): filters['filter_endpoint'] = args['endpointID']		
	if (args['user'] != ''): filters['filter_username'] = args['user']
	if (args['start'] != ''):
		if (args['end'] != ''):
			filters['filter_completion_time'] = "{0},{1}".format(args['start'], args['end'])
		else:
			filters['filter_completion_time'] = "{0}".format(args['start'])
	else:
		if (args['end'] !=''):
			filters['filter_completion_time'] = ",{0}".format(args['end'])

	my_logger.info('FILTERS   :')
	for key in filters:
		msg = '{0}: {1}'.format(key,filters[key])
		my_logger.info(msg)
		email_logmsg("{}\n\n".format(msg))

	return filters

#=========================================================================================
def parse_opts():
	""" Parse command line arguments """

	import argparse
	import textwrap
	
	from datetime import timedelta
	global doprint, task_only

	""" Parse command line arguments """
	desc = "Request transfer metrics from the Globus Transfer API and store the metrics in RDADB."	
	epilog = textwrap.dedent('''\
	Example:
	  - Retrieve transfer metrics for endpoint rda#datashare between 1 Jan - 31 Jan 2017:
	              retrieve_globus_metrics.py -n datashare -s 2017-01-01 -e 2017-01-31	
	''')

	parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=desc, epilog=textwrap.dedent(epilog))
	parser.add_argument('-n', action="store", dest="ENDPOINT", required=True, help='RDA shared endpoint (canonical name), e.g. datashare')
	parser.add_argument('-u', action="store", dest="USERNAME", help='GlobusID username')
	parser.add_argument('-s', action="store", dest="STARTDATE", help='Begin date for search.  Default is 30 days prior.')
	parser.add_argument('-e', action="store", dest="ENDDATE", help='End date for search.  Default is current date.')
	parser.add_argument('-p', action="store", dest="PRINTINFO", help='Print task transfer details.  Default is False.')
	parser.add_argument('-to', action="store_true", dest="TASKONLY", help='Collect task-level metrics only.  Does not collect file-level metrics.')
	
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)

	args = parser.parse_args(sys.argv[1:])
	my_logger.info("{0}: {1}".format(sys.argv[0], args))
	opts = vars(args)

	date_fmt = "%Y-%m-%d"

	# Default arguments.  Start date = 30 days ago, to cover full 30-day history in 
	# Globus database.
	user = ''
	start_date = (datetime.utcnow()-timedelta(days=30)).isoformat()
	end_date = datetime.utcnow().isoformat()
	doprint = bool(False)
	task_only = bool(False)

	if opts['ENDPOINT']:
		if(re.search(r'datashare', opts['ENDPOINT'])):
			endpoint = 'rda#datashare'
		if(re.search(r'stratus', opts['ENDPOINT'])):
			endpoint = 'rda#stratus'
		if(re.search(r'data_request', opts['ENDPOINT'])):
			endpoint = 'rda#data_request'
		endpointID = MyEndpoints[endpoint]
		my_logger.info('ENDPOINT  : {0}'.format(endpoint))
		my_logger.info('ENDPOINT ID: {0}'.format(endpointID))
	if opts['USERNAME']:
		user = opts['USERNAME']
		my_logger.info('USER      : {0}'.format(user))
	if opts['STARTDATE']:
		start_date = format_date(opts['STARTDATE'], date_fmt)
		my_logger.info('START     : {0}'.format(start_date))
	if opts['ENDDATE']:
		end_date = format_date(opts['ENDDATE'], date_fmt)
		my_logger.info('END       : {0}'.format(end_date))
	if opts['PRINTINFO']:
		doprint = bool(True)
	if opts['TASKONLY']:
		task_only = bool(True)
			
	print ('ENDPOINT   :', endpoint)
	print ('ENDPOINT ID:', endpointID)
	print ('USER       :', user)
	print ('START      :', start_date)
	print ('END        :', end_date)
	print ('PRINT      :', doprint)
	print ('TASK ONLY  :', task_only)

	configure_email_log(opts['ENDPOINT'])

	msg_opts = "ENDPOINT   : {}\n".format(endpoint)
	msg_opts += "ENDPOINT ID: {}\n".format(endpointID)
	msg_opts += "USER       : {}\n".format(user)
	msg_opts += "START      : {}\n".format(start_date)
	msg_opts += "END        : {}\n".format(end_date)
	msg_opts += "TASK ONLY  : {}\n".format(task_only)
	email_logmsg(msg_opts)

	return {'endpoint': endpoint, \
	        'endpointID': endpointID, \
            'user': user, \
            'start': start_date, \
            'end': end_date}

#=========================================================================================
def configure_email_log(endpoint):
	""" Set up email logging if dscheck record exists (PBS jobs only) """

	# Check for dscheck record
	condition = "command LIKE '%retrieve_globus_metrics%' and argv LIKE '%{}%'".format(endpoint)
	ckrec = pgget('dscheck', 'cindex,command', condition)
	if (len(ckrec) > 0):
		PGLOG['DSCHECK'] = ckrec
		my_logger.info("[configure_log] dscheck record found for endpoint {0} with dscheck index {1}".format(endpoint, PGLOG['DSCHECK']['cindex']))

#=========================================================================================
def configure_log(**kwargs):
	""" Set up logging configuration """

	LOGFILE = 'retrieve_globus_metrics.log'
	
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

	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

	""" Rotating file handler """
	rfh = logging.handlers.RotatingFileHandler(LOGPATH+'/'+LOGFILE,maxBytes=200000000,backupCount=1)
	rfh.setLevel(level)
	rfh.setFormatter(formatter)
	my_logger.addHandler(rfh)
	
	""" Handler to send log messages to email address (rda-work only) """
	if (socket.gethostname() == 'rda-work.ucar.edu'):
		fromaddr = 'tcram@ucar.edu'
		toaddr = 'tcram@ucar.edu'
		subject = '[retrieve_globus_metrics] Warning/error/critical message'
		emh = logging.handlers.SMTPHandler('localhost', fromaddr, toaddr, subject)
		emh.setLevel(logging.WARNING)
		emh.setFormatter(formatter)
		my_logger.addHandler(emh)
	
	return

#=========================================================================================
""" Set up logging """
my_logger = logging.getLogger(__name__)
configure_log(level='info')

if __name__ == "__main__":
	args = parse_opts()
	filters = set_filters(args)
	main(filters)
	
