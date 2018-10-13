#!/usr/bin/env python
#
##################################################################################
#
#     Title : retrieve_globus_metrics.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 02/04/2015
#   Purpose : Python script to retrieve Globus data transfer metrics for RDA users.
#
#      Note : If running on the geyser nodes, load the required environment modules with 
#             the following commands:
#             module use /glade/u/apps/contrib/modulefiles/
#             module load globus-sdk
#
# Work File : $DSSHOME/bin/retrieve_globus_metrics.py*
# Test File : $DSSHOME/bin/retrieve_globus_metrics_test.py*
#  SVN File : $HeadURL: https://subversion.ucar.edu/svndss/tcram/python/retrieve_globus_metrics.py $
#
##################################################################################

import sys
import socket, re

path1 = "/glade/u/home/rdadata/lib/python"
path2 = "/glade/u/home/tcram/lib/python"
if (path1 not in sys.path):
	sys.path.append(path1)
if (path2 not in sys.path):
	sys.path.append(path2)

from MyGlobus import headers, MyGlobus
from PyDBI import myget, mymget, myadd, myupdt
from globus_utils import load_app_client
from globus_sdk import (TransferClient, TransferAPIError, RefreshTokenAuthorizer,
                        GlobusError, GlobusAPIError, NetworkError)

from datetime import datetime, tzinfo
import pytz
import logging
import logging.handlers
import urllib

# Task list keys to retain
task_keys = ['status','bytes_transferred','task_id','username',\
	         'type','request_time','completion_time','files',\
	         'files_skipped','bytes_transferred',\
	         'source_endpoint','source_host_endpoint','source_host_path',\
	         'destination_endpoint','destination_host_endpoint',\
	         'destination_host_path']

# Keys for individual Globus task IDs
transfer_keys = ['destination_path','source_path', 'DATA_TYPE']

# Endpoint UUIDs
data_requestID = MyGlobus['data_request_ep']
datashareID = MyGlobus['datashare_ep']
                 
#=========================================================================================
def main(filters):

# Get Globus transfer tasks
	my_logger.debug(__name__+': Getting tasks')
	transfer_tasks = get_tasks(filters)
	if doprint: print_doc(transfer_tasks, task_keys)
	my_logger.debug(__name__+': Adding/updating tasks in RDA DB')
	add_tasks('gotask', transfer_tasks)

# Get list of successful transfers for each Globus task id.
	my_logger.debug(__name__+': Getting and adding Globus transfers')
	for i in range(len(transfer_tasks)):
		task_id = transfer_tasks[i]['task_id']
		bytes = transfer_tasks[i]['bytes_transferred']
		my_logger.debug(__name__+': task_id: '+task_id)
		data_transfers = get_successful_transfers(task_id)
		if (len(data_transfers) > 0):
			add_successful_transfers('gofile', data_transfers, task_id, bytes, filters['filter_endpoint'])

	my_logger.debug(__name__+': END')

#=========================================================================================

def get_tasks(filters):
	""" Get list of successful transfer tasks """
	try:
		tasks = []
		tc_authorizer = RefreshTokenAuthorizer(MyGlobus['transfer_refresh_token'], load_app_client())
		tc = TransferClient(authorizer=tc_authorizer)
		for task in tc.endpoint_manager_task_list(num_results=None, **filters):
			tasks.append(task)
	except GlobusAPIError as e:
		msg = ("[get_tasks] Globus API Error\n"
		       "HTTP status: {}\n"
		       "Error code: {}\n"
		       "Error message: {}").format(e.http_status, e.code, e.message)
		my_logger.error(msg)
		raise e
	except NetworkError:
		my_logger.error(("[get_tasks] Network Failure. "
                   "Possibly a firewall or connectivity issue"))
		raise
	except GlobusError:
		logging.exception("[get_tasks] Totally unexpected GlobusError!")
		raise

	return tasks
	
#=========================================================================================
# Insert/update Globus transfer tasks

def add_tasks(go_table, data):
	
# Prepare database records
	if (len(data) >= 1):
		records = create_recs(data, task_keys)
		emails = check_email(data)
		records = update_records(records, emails)
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

	return

#=========================================================================================
# Get list of files transferred successfully

def get_successful_transfers(task_id):

	try:
		transfers = []
		tc_authorizer = RefreshTokenAuthorizer(MyGlobus['transfer_refresh_token'], load_app_client())
		tc = TransferClient(authorizer=tc_authorizer)
		for transfer in tc.endpoint_manager_task_successful_transfers(task_id, num_results=None):
			transfers.append(transfer)
	except GlobusAPIError as e:
		msg = ("[get_successful_transfers] Globus API Error\n"
		       "HTTP status: {}\n"
		       "Error code: {}\n"
		       "Error message: {}").format(e.http_status, e.code, e.message)
		my_logger.error(msg)
		raise e
	except NetworkError:
		my_logger.error(("[get_successful_transfers] Network Failure. "
                   "Possibly a firewall or connectivity issue"))
		raise
	except GlobusError:
		logging.exception("[get_successful_transfers] Totally unexpected GlobusError!")
		raise

	# return all successful transfers
	return transfers

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
	msg = "Error {0}: {1}".format(str(r.status_code), data['message'])
	msg += " Resource: {0}".format(data['resource'])
	my_logger.error(msg)
	error_code = r.headers['x-transfer-api-error']
	
	if (error_code == 'EndpointNotFound' or error_code == 'ServiceUnavailable'):
		sys.exit()
	else:
		return
	
#=========================================================================================
# Parse file names in data_transfers dictionary

def prepare_transfer_recs(data, task_id, bytes, endpoint):
	transfer_recs = []
	size = 0
	
	for i in range(len(data)):
		destination_path = data[i]['destination_path']
		source_path = data[i]['source_path']
		data_type = data[i]['DATA_TYPE']
		pathsplit = source_path.split("/")

		if (endpoint == datashareID):
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
		
		# rda#data_request
		if (endpoint == data_requestID):
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
	my_logger.info("[add_successful_transfers] task_id: {0}".format(task_id))

# Prepare database records

# *** Need to delete records from data['DATA'][i]['source_path'] which are not in RDADB wfile here ***

	if (len(data) >= 1):
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
			if (endpoint == datashareID):
				condition = " WHERE {0} = '{1}' AND {2}='{3}'".format("task_id", records[i]['task_id'], "source_path", records[i]['source_path'])
				myrec = myget(go_table, keys, condition)
				if (len(myrec) > 0):
					if (cmp(records[i],myrec) != 0):
						myupdt(go_table, records[i], condition)
					else:
						my_logger.info("[add_successful_transfers] task_id: "+task_id+" : "+go_table+" DB record exists and is up to date.")
				else:
					myadd(go_table, records[i])
			elif (endpoint == data_requestID):
				dsrqst_count += 1
			else:
				my_logger.warning('[add_successful_transfers] Endpoint {0} not found'.format(endpoint))
				return

	# Insert usage from rda#datashare into table allusage
	if (endpoint == datashareID and len(records) > 0):
		update_allusage(task_id)

	if (endpoint == data_requestID and len(records) > 0):
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
				my_logger.info("[add_successful_transfers] task_id: {0}, rindex {1}: {2} DB record already exists and is up to date.".format(task_id,dsrqst_rec[0]['rindex'],go_table))
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
				my_logger.info("[update_allusage] DB record already exists and is up to date.")
		else:
			myadd(go_table, all_recs[i])

#=========================================================================================
# Define filters to apply in API requests

def set_filters(args):
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

	my_logger.info('FILTERS   :',filters)
	for key in filters:
		my_logger.info('{0} \t {1}'.format(key,filters[key]))

	return filters

#=========================================================================================
# Parse the command line arguments

def parse_opts():
	import argparse
	import textwrap
	
	from datetime import timedelta
	global doprint

	""" Parse command line arguments """
	desc = "Request transfer metrics from the Globus Transfer API and store the metrics in RDADB."	
	epilog = textwrap.dedent('''\
	Example:
	  - Retrieve transfer metrics for endpoint rda#datashare between 1 Jan - 31 Jan 2017:
	              retrieve_globus_metrics.py -n rda#datashare -s 2017-01-01 -e 2017-01-31	
	''')

	parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=desc, epilog=textwrap.dedent(epilog))
	parser.add_argument('-n', action="store", dest="ENDPOINT", required=True, help='RDA shared endpoint (canonical name), e.g. rda#datashare')
	parser.add_argument('-u', action="store", dest="USERNAME", help='GlobusID username')
	parser.add_argument('-s', action="store", dest="STARTDATE", help='Begin date for search.  Default is 30 days prior.')
	parser.add_argument('-e', action="store", dest="ENDDATE", help='End date for search.  Default is current date.')
	parser.add_argument('-p', action="store", dest="PRINTINFO", help='Print task transfer details.  Default is False.')
	
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)

	args = parser.parse_args(sys.argv[1:])
	my_logger.info("{0}: {1}".format(sys.argv[0], args))
	opts = vars(args)

	date_fmt = "%Y-%m-%d"

	# Default arguments.  Start date = 30 days ago, to cover full 30-day history in 
	# Globus database.
	endpoint = MyGlobus['data_request_legacy']
	endpointID = MyGlobus['data_request_ep']
	user = ''
	start_date = (datetime.utcnow()-timedelta(days=30)).isoformat()
	end_date = datetime.utcnow().isoformat()
	doprint = bool(False)

	if opts['ENDPOINT']:
		if(opts['ENDPOINT'] == 'rda#datashare'):
			endpoint = opts['ENDPOINT']
			endpointID = MyGlobus['datashare_ep']
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
			
	print 'ENDPOINT   :', endpoint
	print 'ENDPOINT ID:', endpointID
	print 'USER       :', user
	print 'START      :', start_date
	print 'END        :', end_date
	print 'PRINT      :', doprint

	return {'endpoint': endpoint, \
	        'endpointID': endpointID, \
            'user': user, \
            'start': start_date, \
            'end': end_date}

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
	for i in range(len(data)):
		for key in data[i].data:
			if key in keys:
				go_dict[key] = data[i].data[key]
			else:
				continue
		records.append(go_dict)
		go_dict = {}
	return records
	
#=========================================================================================
# Check for user's email address in the gouser table.  Add to records dictionary if found.

def check_email(data):
	emails = []
	for i in range(len(data)):
		condition = " WHERE {0}='{1}' AND {2}='{3}'".format("username", data[i]['username'],"status","ACTIVE")
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
	for i in range(len(data)):
		print '\n'
		for key in data[i]:
			if key in keys:
				print key, '\t', data[i][key]
			else:
				continue

#=========================================================================================
# Configure log file

def configure_log(**kwargs):
	""" Set up log file """
	LOGPATH = '/glade/scratch/tcram/logs/globus/'
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
	handler = logging.handlers.RotatingFileHandler(LOGPATH+'/'+LOGFILE,maxBytes=200000000,backupCount=1)
	handler.setLevel(level)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	my_logger.addHandler(handler)
	
	return

#=========================================================================================
""" Set up logging """
my_logger = logging.getLogger(__name__)
configure_log(level='debug')

if __name__ == "__main__":
	args = parse_opts()
	filters = set_filters(args)
	main(filters)
	