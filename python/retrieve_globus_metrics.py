#!/usr/bin/env python
#
##################################################################################
#
#     Title : retrieve_globus_metrics.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 02/04/2015
#   Purpose : Python script to retrieve Globus data transfer metrics for RDA users.
#
# Work File : $DSSHOME/bin/retrieve_globus_metrics.py*
# Test File : $DSSHOME/bin/retrieve_globus_metrics_test.py*
#  SVN File : $HeadURL: https://subversion.ucar.edu/svndss/tcram/python/retrieve_globus_metrics.py $
#
##################################################################################

import requests
import os, sys
from PyDBI import myget, mymget, myadd, myupdt
import globusonline.transfer.api_client
from datetime import datetime, tzinfo
import pytz
import logging
import logging.handlers
import re
import urllib
import time

LOGPATH = '/glade/p/rda/work/tcram/logs/globus'
LOGFILE = 'retrieve_globus_metrics.log'
ERRLOG = 'retrieve_globus_metrics.err'
DBGLOG  = 'retrieve_globus_metrics.dbg'

url = 'https://transfer.api.globusonline.org/v0.10/'
token_file = open('/glade/u/home/rdadata/dssdb/tmp/.globus/goauth-token', 'r')
gotoken = token_file.read().rstrip('\\n')
headers = {'Authorization':'Globus-Goauthtoken '+gotoken}

# Task list keys to retain
task_keys = ['status','bytes_transferred','task_id','username',\
	         'type','request_time','completion_time','files',\
	         'files_skipped','bytes_transferred',\
	         'source_endpoint','source_host_endpoint','source_host_path',\
	         'destination_endpoint','destination_host_endpoint',\
	         'destination_host_path']

# Keys for individual Globus task IDs
transfer_keys = ['destination_path','source_path', 'DATA_TYPE']
                 
#=========================================================================================
def main(filters):

# Get Globus transfer tasks
	data_tasks = get_tasks(filters)
	if doprint: print_doc(data_tasks, task_keys)
	add_tasks('gotask', data_tasks)

# Get list of successful transfers for each Globus task id.
	for i in range(len(data_tasks['DATA'])):
		task_id = data_tasks['DATA'][i]['task_id']
		bytes = data_tasks['DATA'][i]['bytes_transferred']
		data_transfers = get_successful_transfers(task_id)
		if (len(data_transfers) > 0):
			add_successful_transfers('gofile', data_transfers, task_id, bytes, filters['filter_endpoint'])

	my_logger.info(__name__+': END')

#=========================================================================================
# Get Globus transfer tasks

def get_tasks(filters):
	my_debug.debug('[get_tasks] Getting tasks')
	resource = 'endpoint_manager/task_list'
	r = requests.get(url+resource, headers=headers, params=filters)
	data = r.json()
	if (r.status_code >= 400):
		handle_error(r, data)
	else:
		data_tasks = {}
		data_tasks.update(data)

# Check for additional pages in task_list response. Rinse and repeat until 'has_next_page'
# is false.
	filters_next = filters
	while (data['has_next_page']):
		filters_next['last_key'] = str(data['last_key']).encode('utf8')
		r = requests.get(url+resource, headers=headers, params=filters_next)
		data = r.json()
		if (r.status_code >= 400):
			handle_error(r, data)
		else:
			data_tasks['DATA'].extend(data['DATA'])

	return data_tasks
	
#=========================================================================================
# Insert/update Globus transfer tasks

def add_tasks(go_table, data):
	my_debug.debug('[add_tasks] Adding/updating tasks in RDA DB')
	
# Prepare database records
	if (len(data['DATA']) >= 1):
		records = create_recs(data, task_keys)
		emails = check_email(data)
		records = update_records(records,emails)
	else:
		my_logger.warning("[add_tasks] There is no data in the return document.")
		sys.exit()
	
	# Check if record already exists for each task id. Update if necessary.
	task_keys.append('email')
	for i in range(len(records)):
		condition = " WHERE {0} = '{1}'".format("task_id", records[i]['task_id'])
		myrec = myget(go_table, task_keys, condition)
		if (len(myrec) > 0):
			try:
				myrec['request_time'] = myrec['request_time'].replace(tzinfo=pytz.utc).isoformat()
				myrec['completion_time'] = myrec['completion_time'].replace(tzinfo=pytz.utc).isoformat()
			except KeyError:
				pass
			if (cmp(records[i],myrec) != 0):
				records[i]['request_time'] = records[i]['request_time'][:19]
				records[i]['completion_time'] = records[i]['completion_time'][:19]
				myupdt(go_table, records[i], condition)
			else:
				my_logger.info("[add_tasks] DB record for task ID {0} exists and is up to date.".format(records[i]['task_id']))
		else:
			records[i]['request_time'] = records[i]['request_time'][:19]
			records[i]['completion_time'] = records[i]['completion_time'][:19]
			myadd(go_table, records[i])

#=========================================================================================
# Get list of files transferred successfully under a single task ID

def get_successful_transfers(task_id):
	my_debug.debug("[get_successful_transfers] Processsing task_id: {0}".format(task_id))
	resource = 'endpoint_manager/task/'+task_id+'/successful_transfers'
	limit = 1000
	params = {'limit':limit}
	r = requests.get(url+resource, headers=headers, params=params)
	data = r.json()
	offset = data['next_marker'] - limit
	data_transfers = {}
	
	if (r.status_code >= 400):
		handle_error(r, data)
		return data_transfers
	else:	
		data_transfers.update(data)
	
	# Check for additional pages.  Append response to data_transfers.
		while (data['next_marker']):
			next_marker = data['next_marker']
			my_debug.debug("[get_successful_transfers] next_marker: {0}".format(next_marker))
			if (next_marker % (limit*10) == offset):
				my_debug.debug("[get_successful_transfers] One second sleep timer")
				time.sleep(1)
			params['marker'] = next_marker
			r = requests.get(url+resource, headers=headers, params=params)
			data = r.json()
			if (r.status_code >= 400):
				handle_error(r, data)
			else:
				data_transfers['DATA'].extend(data['DATA'])

	# return all successful transfers
		return data_transfers

#=========================================================================================
# Parse file names in data_transfers dictionary

def prepare_transfer_recs(data, task_id, bytes, endpoint):
	transfer_recs = []
	size = 0
	
	for i in range(len(data['DATA'])):
		destination_path = data['DATA'][i]['destination_path']
		source_path = data['DATA'][i]['source_path']
		data_type = data['DATA'][i]['DATA_TYPE']
		pathsplit = source_path.split("/")

		if (endpoint == 'rda#datashare'):
		    # Query file size from wfile.data_size
			dsid = pathsplit[1]
			wfile = urllib.unquote("/".join(pathsplit[2:]))
			condition = " WHERE {0}='{1}' AND {2}='{3}'".format("dsid", dsid, "wfile", wfile)
			myrec = myget('wfile', ['data_size'], condition)
			if (len(myrec) > 0):
				transfer_recs.append({
				             unicode('destination_path'):destination_path,
				             unicode('source_path'):source_path,
				             unicode('DATA_TYPE'):data_type,
				             unicode('task_id'):task_id,
			                 unicode('file_name'):urllib.unquote(pathsplit[-1]),
			                 unicode('rindex'):None,
			                 unicode('dsid'):dsid,
			                 unicode('size'):myrec['data_size'],
			                 unicode('count'):1})
		
		if (endpoint == 'rda#data_request'):
			searchObj = re.search(r'\d+$', pathsplit[2])
			rindex = int(searchObj.group(0))
			condition = " WHERE {0}='{1}'".format("rindex", rindex)
			myrec = myget('dsrqst', ['dsid'], condition)
			if (len(myrec) == 0):
				myrec = myget('dspurge', ['dsid'], condition)
			if (len(myrec) > 0):
				dsid = myrec['dsid']
			else:
				logger.warning("Request index {0} not found".format(rindex))
				dsid = None
			
			transfer_recs.append({
				         unicode('destination_path'):destination_path,
				         unicode('source_path'):source_path,
				         unicode('DATA_TYPE'):data_type,
			             unicode('task_id'):task_id,
			             unicode('file_name'):pathsplit[2],
			             unicode('rindex'):rindex,
			             unicode('dsid'):dsid,
			             unicode('size'):bytes,
			             unicode('count'):None})
	
	return transfer_recs

#=========================================================================================
# Insert/update list of files transferred successfully

def add_successful_transfers(go_table, data, task_id, bytes, endpoint):
	my_debug.debug("[add_successful_transfers] Processing task_id: {0}".format(task_id))

# Prepare database records

# *** Need to delete records from data['DATA'][i]['source_path'] which are not in RDADB wfile here ***

	if (len(data['DATA']) >= 1):
		records = prepare_transfer_recs(data, task_id, bytes, endpoint)
		if (len(records) == 0):
			my_logger.warning("[add_successful_transfers] transfer_recs is empty")
			return
	else:
		my_logger.warning("[add_successful_transfers] There is no data in the return document.")
		return
	
	# Check if record already exists. Update if necessary.
	keys = transfer_keys
	keys.extend(['task_id','file_name','rindex','dsid','size','count'])
	
	dsrqst_count = 0
	
	# Skip files named index.html, .htaccess, *.email_notice, *.csh, *.pl
	for i in range(len(records)):
		searchObj = re.search(r'(index\.html)$|(htaccess)$|(\.email_notice)$|(\.csh)$', records[i]['source_path'])
		if searchObj:
			continue
		else:
			if (endpoint == 'rda#datashare'):
				condition = " WHERE {0} = '{1}' AND {2}='{3}'".format("task_id", records[i]['task_id'], "source_path", records[i]['source_path'])
				myrec = myget(go_table, keys, condition)
				if (len(myrec) > 0):
					if (cmp(records[i],myrec) != 0):
						myupdt(go_table, records[i], condition)
					else:
						my_debug.debug("[add_successful_transfers] task_id: "+task_id+" : "+go_table+" DB record exists and is up to date.")
				else:
					myadd(go_table, records[i])
			elif (endpoint == 'rda#data_request'):
				dsrqst_count += 1
			else:
				my_logger.warning('[add_successful_transfers] Endpoint {0} not found'.format(endpoint))
				return

	# Insert usage from rda#datashare into table allusage
	if (endpoint == 'rda#datashare' and len(records) > 0):
		update_allusage(task_id)

	if (endpoint == 'rda#data_request' and len(records) > 0):
		dsrqst_rec = []
		pathsplit = records[0]['source_path'].split("/")
		file_name = pathsplit.pop()
		source_path = "/".join(pathsplit)
		dsrqst_rec.append({unicode('task_id'): task_id,
		                   unicode('DATA_TYPE'): records[0]['DATA_TYPE'],
		                   unicode('destination_path'): records[0]['destination_path'],
		                   unicode('source_path'): source_path,
		                   unicode('file_name'): records[0]['file_name'],
		                   unicode('rindex'): records[0]['rindex'],
		                   unicode('dsid'): records[0]['dsid'],
		                   unicode('size'): bytes,
		                   unicode('count'): dsrqst_count
		                   })
		condition = " WHERE {0}='{1}' AND {2}={3}".format("task_id",task_id,"rindex", dsrqst_rec[0]['rindex'])
		myrec = myget(go_table, keys, condition)
		if (len(myrec) > 0):
			if (cmp(dsrqst_rec, myrec) != 0):
				myupdt(go_table, dsrqst_rec[0], condition)
			else:
				my_debug.debug("[add_successful_transfers] task_id: {0}, rindex {1}: {2} DB record already exists and is up to date.".format(task_id,dsrqst_rec[0]['rindex'],go_table))
		else:
			myadd(go_table, dsrqst_rec[0])

#=========================================================================================
# Insert/update usage in the table allusage

def update_allusage(task_id):
	from time import strftime
	go_table = 'allusage'
	method = 'GLOB'
	source = 'G'
	all_recs = []
	
	condition = " WHERE {0}='{1}'".format("task_id",task_id)
	myrec = myget('gotask', ['email','completion_time', 'QUARTER(completion_time)'], condition)
	if (len(myrec) > 0):
		email = myrec['email']
		completion_time = myrec['completion_time']
		quarter = myrec['QUARTER(completion_time)']
	else:
		my_logger.warning("[update_allusage] Task ID {0} not found.".format(task_id))
		return
	
	# Format date and time.
	completion_date = myrec['completion_time'].strftime("%Y-%m-%d")
	completion_time = myrec['completion_time'].strftime("%H:%M:%S")
	
	# Get user email, org_type, and country
	condition = " WHERE {0}='{1}' AND {2} IS NULL".format("email",email,"end_date")
	myrec = myget('ruser',['org_type','country'], condition)
	if (len(myrec) > 0):
		org_type = myrec['org_type']
		country = myrec['country']
	else:
		my_logger.warning("[update_allusage] User email {0} not found in table ruser.".format(email))
		return
	
	# Get dsid and calculate size.  Query table gofile and handle multiple records, if
	# necessary.
	condition = " WHERE {0}='{1}' GROUP BY {2}".format("task_id",task_id,"dsid")
	myrecs = mymget('gofile',['dsid','SUM(size)'], condition)
	if (len(myrecs) > 0):
		for i in range(len(myrecs)):
			all_recs.append({unicode('email'): email,unicode('org_type'): org_type,unicode('country'): country, unicode('dsid'): myrecs[i]['dsid'],unicode('date'): completion_date,unicode('time'): completion_time,unicode('quarter'): quarter, unicode('size'): int(myrecs[i]['SUM(size)']), unicode('method'): method,unicode('source'): source,unicode('midx'): 0,unicode('ip'): None})
	else:
		my_logger.warning("[update_allusage] Task ID {0} not found in table gofile.".format(task_id))
		return

	for i in range(len(all_recs)):
		dsid = all_recs[i]['dsid']
		condition = " WHERE {0}='{1}' AND {2}='{3}' AND {4}='{5}' AND {6}='{7}' AND {8}='{9}'".format("email",email,"dsid",dsid,"date",completion_date,"time",completion_time,"method",method)
		myrec = myget(go_table, ['*'], condition)
		if (len(myrec) > 0):
			myrec['date'] = myrec['date'].strftime("%Y-%m-%d")
			myrec['time'] = str(myrec['time'])
			if (cmp(all_recs[i], myrec) != 0):
				myupdt(go_table, all_recs[i], condition)
			else:
				my_debug.debug("[update_allusage] DB record already exists and is up to date.")
		else:
			myadd(go_table, all_recs[i])

#=========================================================================================
# Define filters to apply in API requests

def set_filters(args):
	my_debug.debug('[set_filters] Defining Globus API filters')
	filters = {}
	if (args['endpoint']): filters['filter_endpoint'] = args['endpoint']		
	if (args['user'] != ''): filters['filter_username'] = args['user']
	if (args['start'] != ''):
		if (args['end'] != ''):
			filters['filter_completion_time'] = args['start'] + ',' + args['end']
		else:
			filters['filter_completion_time'] = args['start']
	else:
		if (args['end'] !=''):
			filters['filter_completion_time'] = ',' + args['end']

	my_logger.info('FILTERS   :',filters)
	for key in filters:
		my_logger.info('{0} \t {1}'.format(key,filters[key]))

	return filters

#=========================================================================================
# Parse the command line arguments

def parse_opts(argv):
	import getopt
	from datetime import timedelta
	global doprint
	global my_debug

	usg = 'Usage: retrieve_globus_metrics.py -n ENDPOINT -u USERNAME -s STARTDATE -e ENDDATE'	
	date_fmt = "%Y-%m-%d"
	thirtyDays = timedelta(days=30)
	thirtyDaysAgo = datetime.now(tz=pytz.utc) - thirtyDays

	# Default arguments.  Start date = 30 days ago, to cover full 30-day history in 
	# Globus database.
	endpoint = 'rda#data_request'
	user = ''
	start_date = thirtyDaysAgo.isoformat()
	end_date = datetime.now(tz=pytz.utc).isoformat()
	doprint = bool(False)
	rem = ''
	
	opts, rem = getopt.getopt(argv, 'n:u:s:e:p:b', ['endpoint=','user=','startdate=','enddate=','print','debug'])
	
	for opt, arg in opts:
		if opt in ('-n', '--endpoint'):
			endpoint = arg
			my_logger.info('ENDPOINT  : {0}'.format(endpoint))
		elif opt in ('-u', '--user'):
			user = arg
			my_logger.info('USER      : {0}'.format(user))
		elif opt in ('-s', '--startdate'):
			start_date = format_date(arg, date_fmt)
			my_logger.info('START     : {0}'.format(start_date))
		elif opt in ('-e', '--enddate'):
			end_date = format_date(arg, date_fmt)
			my_logger.info('END       : {0}'.format(end_date))
		elif opt in ('-p', '--print'):
			doprint = bool(True)
		elif opt in ('-b', '--debug'):
			my_debug = mydbg(LOGPATH, DBGLOG)
		elif opt in ('-h', '--help'):
			print usg
	
	print 'ENDPOINT  :', endpoint
	print 'USER      :', user
	print 'START     :', start_date
	print 'END       :', end_date
	print 'PRINT     :', doprint
	print 'REMAINING :', rem

	return {'endpoint': endpoint, \
            'user': user, \
            'start': start_date, \
            'end': end_date, \
            'rem': rem}

#=========================================================================================
# Convert date string into ISO 8601 format (YYYY-MM-DDTHH:MM:SS)

def format_date(date_str, fmt):
	from time import strptime
	
	date = strptime(date_str, fmt)
	isodate = datetime(date[0], date[1], date[2]).isoformat()
	
	return isodate

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
# Check for user's email address in the gouser table.  Add to records dictionary if found.

def check_email(data):
	emails = []
	for i in range(len(data['DATA'])):
		condition = " WHERE {0}='{1}' AND {2}='{3}'".format("username", data['DATA'][i]['username'],"status","ACTIVE")
		myrec = myget('gouser', ['email'], condition)
		if (myrec.has_key('email')):
			emails.append(myrec)
		else:
			emails.append({'email':None})
	return emails
	
#=========================================================================================
# Update the records list of task dictionaries

def update_records(list1,list2):
	if (len(list1) != len(list2)):
		my_logger.warning("[update_records] Mismatch between len list1 ({0}) and len list2 ({1})".format(len(list1),len(list2)))
		return

	for i in range(len(list1)):
		list1[i].update(list2[i])
	return list1
	
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
# Handle errors returned by API resource

# Example:
# Verify that task id exists.  Response will be as follows if not:
# r.status_code = 404
# r.headers['x-transfer-api-error'] = 'TaskNotFound'
# data['code'] = 'TaskNotFound'
# data['message'] = 'Task ID <task_id> not found'
# data['resource'] = '/endpoint_manager/task/<task_id>/successful_transfers'

# Also, for failed tasks, the task ID will exist, but response will have zero content:
# len(data['DATA']) = 0

def handle_error(r, data):
	msg = "Error {0}: {1}, {2}".format(str(r.status_code), data['code'], data['message'])
	msg += " Resource: {0}".format(data['resource'])
	my_err.error(msg)
	error_code = r.headers['x-transfer-api-error']
	
	if (error_code == 'EndpointNotFound' or error_code == 'ServiceUnavailable'):
		sys.exit()
	else:
		return
	
#=========================================================================================
# Open log file
# level = DEBUG, INFO, WARNING, ERROR, or CRITICAL

def mylog(logpath, logfile, level):
	loggerName = 'GlobusMetricsLog'
	my_logger = logging.getLogger(loggerName)
	num_level = getattr(logging, level.upper())
	my_logger.setLevel(num_level)
	handler = logging.handlers.RotatingFileHandler(logpath+'/'+logfile,maxBytes=1000000000,backupCount=10)
	handler.setLevel(num_level)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - line %(lineno)d - %(message)s')
	handler.setFormatter(formatter)
	my_logger.addHandler(handler)
	return my_logger
 
#=========================================================================================
# Open error log file

def myerr(logpath, errlog):
	loglevel = 'ERROR'
	loggerName = 'GlobusMetricsErrorLog'
	my_err = logging.getLogger(loggerName)
	num_level = getattr(logging, loglevel.upper())
	my_err.setLevel(num_level)
	handler = logging.handlers.RotatingFileHandler(logpath+'/'+errlog,maxBytes=1000000000,backupCount=10)
	handler.setLevel(num_level)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - line %(lineno)d - %(message)s')
	handler.setFormatter(formatter)
	my_err.addHandler(handler)
	return my_err
 
#=========================================================================================
# Open debug log file

def mydbg(logpath, dbglog):
	loglevel = 'DEBUG'
	loggerName = 'GlobusMetricsDebug'
	my_debug = logging.getLogger(loggerName)
	num_level = getattr(logging, loglevel.upper())
	my_debug.setLevel(num_level)
	handler = logging.handlers.RotatingFileHandler(logpath+'/'+dbglog,maxBytes=1000000000,backupCount=10)
	handler.setLevel(num_level)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - line %(lineno)d - %(message)s')
	handler.setFormatter(formatter)
	my_debug.addHandler(handler)
	return my_debug
 
#=========================================================================================

if __name__ == "__main__":
	my_logger = mylog(LOGPATH, LOGFILE, 'INFO')
	my_err = myerr(LOGPATH, ERRLOG)
	args = parse_opts(sys.argv[1:])
	filters = set_filters(args)
	main(filters)
	