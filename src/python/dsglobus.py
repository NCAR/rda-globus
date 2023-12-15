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

import os, sys, pwd

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
import select
import textwrap
import six
from datetime import datetime

from MyGlobus import MyGlobus, MyEndpoints, LOGPATH

from globus_sdk import (TransferClient, TransferData, DeleteData, 
						RefreshTokenAuthorizer, AuthClient, 
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
def get_transfer_client(client_id):
	""" Instantiate a Globus Transfer client """
	
	if client_id is None:
		my_logger.error("[get_transfer_client] Missing client_id from input.")
		sys.exit(1)

	client = load_client(client_id)
	tokens = get_tokens(client_id)
	transfer_refresh_token = tokens['transfer_rt']

	tc_authorizer = RefreshTokenAuthorizer(transfer_refresh_token, client)
	transfer_client = TransferClient(authorizer=tc_authorizer)

	return transfer_client
	
#=========================================================================================
def get_auth_client(client_id):
	""" Instantiate a Globus Auth client """
	
	if client_id is None:
		msg = "[get_transfer_client] Missing client_id."
		my_logger.error(msg)
		sys.exit(1)

	client = load_client(client_id)
	tokens = get_tokens(client_id)
	auth_refresh_token = tokens['auth_rt']

	ac_authorizer = RefreshTokenAuthorizer(auth_refresh_token, client)
	auth_client = AuthClient(authorizer=ac_authorizer)

	return auth_client
	
#=========================================================================================
def get_client_id(action):
	""" Get valid client ID based on command-line or JSON input action """
	
	client_map = {
			"ls": "rda_quasar_client_id",
			"transfer": "rda_quasar_client_id",
			"tb": "rda_quasar_client_id",
			"dr": "rda_quasar_client_id",
			"tb-quasar" : "rda_quasar_client_id",
			"dr-quasar" : "rda_quasar_client_id",
			"gt": "rda_quasar_client_id",
			"tl": "rda_quasar_client_id",
			"delete": "rda_quasar_client_id",
			"mkdir": "rda_quasar_client_id",
			"rename": "rda_quasar_client_id",
			"cancel": "rda_quasar_client_id"
	}

	if action is None:
		msg = "[get_client_id] Missing action in input argument."
		my_logger.error(msg)
		sys.exit(1)
	
	if action in client_map:
		client_id = MyGlobus[client_map[action]]
	else:
		msg = "[get_client_id] Unknown action: {}.  Cannot map to valid client ID.".format(action)
		my_logger.error(msg)
		sys.exit(1)

	return client_id

#=========================================================================================
def load_client(client_id):
	""" Load the correct Globus client based on client ID """

	if client_id is None:
		my_logger.error("[load_client] Missing client_id from input.")
		sys.exit(1)
	
	if client_id == MyGlobus['client_id']:
		client = load_app_client()
	else:
		client = load_rda_native_client(client_id)
	
	return client

#=========================================================================================
def get_tokens(client_id):
	if client_id is None:
		my_logger.error("[load_client] Missing client_id from input.")
		sys.exit(1)

	if client_id == MyGlobus['rda_quasar_client_id']:
		transfer_rt = MyGlobus['transfer_rt_quasar']
		auth_rt = MyGlobus['auth_rt_quasar']
	elif client_id == MyGlobus['client_id']:
		transfer_rt = MyGlobus['transfer_refresh_token']
		auth_rt = MyGlobus['auth_refresh_token']
	else:
		my_logger.error("[get_tokens] Unknown client ID")
		sys.exit(1)

	tokens = {'transfer_rt': transfer_rt,
	          'auth_rt': auth_rt}

	return tokens

#=========================================================================================
def do_action(data):
	""" Run operations based on command line or JSON input """
	
	try:
		command = data['action']
	except KeyError:
		msg = "[do_action] 'action' missing from JSON or command-line input.  Run dsglobus -h for usage instructions."
		my_logger.error(msg)
		sys.exit(1)
	
	dispatch = {
			"ls": list_endpoint_files,
			"transfer": submit_rda_transfer,
			"tb": submit_rda_transfer,
			"dr": submit_rda_transfer,
			"tb-quasar" : submit_rda_transfer,
			"dr-quasar" : submit_rda_transfer,
			"gt": get_task_info,
			"tl": task_list,
			"delete": submit_rda_delete,
			"mkdir": make_directory,
			"rename": rename_multiple_filedir,
			"cancel": task_cancel
	}
	
	""" Get client ID and add it to data dict """
	data.update({'client_id': get_client_id(command)})
	
	if command in dispatch:
		command = dispatch[command]
	else:
		msg = "[do_action] command {} not found.".format(command)
		my_logger.error(msg)
		sys.exit(1)
	
	return command(data)

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
def submit_rda_transfer(data):
	""" General data transfer to RDA endpoints.  Input should be JSON formatted input 
	    if transferring multiple files. """

	try:
		source_endpoint = get_endpoint_by_name(data['source_endpoint'])
		destination_endpoint = get_endpoint_by_name(data['destination_endpoint'])
	except KeyError:
		my_logger.error("[submit_rda_transfer] source_endpoint and/or destination_endpoint missing from input.")
		sys.exit(1)
	try:
		label = data['label']
	except KeyError:
		label=''
	if 'verify_checksum' in data:
		verify_checksum = data['verify_checksum']
	else:
		verify_checksum = False
	try:
		files = data['files']
	except KeyError:
		my_logger.error("[submit_rda_transfer] Files missing from JSON or command-line input")
		sys.exit(1)

	try:
		tc = get_transfer_client(data['client_id'])
	except KeyError:
		my_logger.error("[submit_rda_transfer] client_id is missing from input.")
		sys.exit(1)
		
	transfer_data = TransferData(transfer_client=tc,
							     source_endpoint=source_endpoint,
							     destination_endpoint=destination_endpoint,
							     label=label,
							     verify_checksum=verify_checksum)

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
def submit_rda_delete(data):
	""" Delete files and/or directories from RDA endpoints.  Input should be JSON formatted input 
	    if transferring multiple files. Command line input can be used if deleting a
	    single file/directory with the action --delete. """

	try:
		target_endpoint = get_endpoint_by_name(data['endpoint'])
	except KeyError:
		my_logger.error("[submit_rda_delete] Endpoint name/ID missing from input.")
		raise
	try:
		label = data['label']
	except KeyError:
		label=''
	try:
		files = data['files']
	except KeyError:
		my_logger.error("[submit_rda_delete] File(s) missing from JSON or command-line input")
		raise
	try:
		tc = get_transfer_client(data['client_id'])
	except KeyError:
		my_logger.error("[submit_rda_delete] client_id is missing from input.")
		raise
	
	delete_data = DeleteData(tc, target_endpoint, label=label)

	for i in range(len(files)):
		target_file = files[i]
		delete_data.add_item(target_file)

	try:
		delete_result = tc.submit_delete(delete_data)
		task_id = delete_result['task_id']
	except GlobusAPIError as e:
		msg = ("[submit_rda_delete] Globus API Error\n"
		       "HTTP status: {}\n"
		       "Error code: {}\n"
		       "Error message: {}").format(e.http_status, e.code, e.message)
		my_logger.error(msg)
		raise e
	except NetworkError:
		my_logger.error(("[submit_rda_delete] Network Failure. "
                   "Possibly a firewall or connectivity issue"))
		raise
	except GlobusError:
		logging.exception("[submit_rda_delete] Totally unexpected GlobusError!")
		raise
	
	msg = "{0}\nTask ID: {1}".format(delete_result['message'], task_id)
	my_logger.info(msg)
	print(msg)
	
	return delete_result

#=========================================================================================
def rename_multiple_filedir(data):
	""" Renames files and/or directories on an endpoint. This function takes 
	    multiple file name pairs as input, where the input key 'files' is a list 
	    specifying individual dicts of 'old_path' and 'new_path'.  Example:
	    
	    files = [
	              {
	                "old_path": "/path/to/old/file/file_1_old.txt",
	                "new_path": "/path/to/old/file/file_1_new.txt"
	               }
	              {
	                "old_path": "/path/to/old/file/file_2_old.txt",
	                "new_path": "/path/to/old/file/file_2_new.txt"
	               }
	              {
	                "old_path": "/path/to/old/file/file_3_old.txt",
	                "new_path": "/path/to/old/file/file_3_new.txt"
	               }	              
	            ]
	"""

	try:
		endpoint = get_endpoint_by_name(data['endpoint'])
		files = data['files']
	except KeyError:
		msg = "[rename_filedir] Endpoint name or file(s) missing from JSON or command-line input"
		my_logger.error(msg)
		sys.exit(1)
	try:
		tc = get_transfer_client(data['client_id'])
	except KeyError:
		my_logger.error("[rename_multiple_filedir] client_id is missing from input.")
		raise
	
	responses = []
	for i in range(len(files)):
		old_path = files[i]['old_path']
		new_path = files[i]['new_path']
		rename_response = tc.operation_rename(endpoint, oldpath=old_path, newpath=new_path)

		msg = "old file: {0}\nnew file: {1}\n{2}".format(old_path, new_path, rename_response['message'])
		my_logger.info(msg)
		print(msg)

		responses.append(rename_response)
	
	return responses

#=========================================================================================
def make_directory(data):
	""" Creates a directory on an endpoint. """

	try:
		endpoint = get_endpoint_by_name(data['endpoint'])
		path = data['path']
	except KeyError:
		my_logger.error("[make_directory] Endpoint name or path missing from JSON or command-line input")
		raise

	try:
		tc = get_transfer_client(data['client_id'])
	except KeyError:
		my_logger.error("[make_directory] client_id is missing from input.")
		raise
	
	""" Print warning message and return gracefully if directory already exists. """
	try:
		mkdir_response = tc.operation_mkdir(endpoint, path=path)
		msg = "{}".format(mkdir_response['message'])
		my_logger.info(msg)
		print(msg)
	except GlobusAPIError as e:
		msg = ("[make_directory] Globus API Error\n"
		       "HTTP status: {}\n"
		       "Error code: {}\n"
		       "Error message: {}").format(e.http_status, e.code, e.message)
		my_logger.error(msg)
		if 'Exists' in e.code:
			print(msg)
			return e
		else:
			raise e
	
	return mkdir_response

#=========================================================================================
def get_task_info(data):
	""" Get Globus task info for a specified task ID """
	if 'task_id' not in data:
		msg = "[get_task_info] Task ID missing from input."
		my_logger.error(msg)
		sys.exit(1)

	try:
		tc = get_transfer_client(data['client_id'])
	except KeyError:
		my_logger.error("[get_task_info] client_id is missing from input.")
		raise
	
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
		("Verify Checksum", "verify_checksum"),
	]
	successful_transfer_fields = [
		("Source Path", "source_path"),
		("Destination Path", "destination_path"),
	]

	fields = (common_fields
			  + (completed_fields if task_info["completion_time"] else active_fields)
			  + (delete_fields if task_info["type"] == "DELETE" else transfer_fields)			  
			  )

	colon_formatted_print(task_info, fields)

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
	try:
		limit = data['limit']
	except KeyError:
		limit = None

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

	try:
		tc = get_transfer_client(data['client_id'])
	except KeyError:
		my_logger.error("[task_list] client_id is missing from input.")
		raise

	list_response = tc.task_list(num_results=limit, filter=filter_string[:-1])
	print_table(list_response, fields)

	return list_response

#=========================================================================================
def task_cancel(data):
	""" Cancel a Globus task """
	
	try:
		tc = get_transfer_client(data['client_id'])
	except KeyError:
		my_logger.error("[task_cancel] client_id is missing from input.")
		raise
	try:
		task_id = data['task_id']
	except KeyError:
		my_logger.error("[task_cancel] Task ID missing from JSON or command-line input")
		sys.exit(1)

	cancel_response = tc.cancel_task(task_id)

	msg = "Task ID: {0}\n{1}".format(task_id, cancel_response['message'])
	my_logger.info(msg)
	print(msg)
	
	return cancel_response

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

	try:
		endpoint = get_endpoint_by_name(data['endpoint'])
	except KeyError:
		my_logger.error("[list_endpoint_files] Endpoint name/ID missing from input.")
		
	try:
		ls_params = {"path": data['path']}
	except KeyError:
		my_logger.error("[list_endpoint_files] Path missing from input.")
		raise
	if 'filter_pattern' in data and data['filter_pattern'] is not None:
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

	try:
		tc = get_transfer_client(data['client_id'])
	except KeyError:
		my_logger.error("[task_cancel] client_id is missing from input.")
		raise

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
	
	desc = "Manage RDA Globus shared endpoints and endpoint permissions."	
	epilog = textwrap.dedent('''\
	======================================================================================
	Examples:
	  - Transfer data from GLADE to the NCAR Quasar tape system.  Required arguments: 
	    --transfer, --source-endpoint, --destination-endpoint, --source-file, and 
	    --destination-file:
	    
	        dsglobus --transfer --source-endpoint 'rda-glade' --destination-endpoint 'rda-quasar' --source-file /data/ds999.9/file.txt --destination-file /ds999.9/file.txt
	  			 
	  - List files on the 'NCAR RDA Quasar' endpoint.  Required arguments: --list-files,
	    --endpoint, --path:

	        dsglobus --list-files --endpoint 'NCAR RDA Quasar' --path /ds999.9/cmorph_v1.0/2019

	  - Get detailed information for an individual transfer task.  Required arguments:
	    --get-task, --task-id:
	    
	        dsglobus --get-task --task-id <TASK_ID>

	  - List transfer tasks completed in February 2021.  Required argument: --task-list.
	    Optional filtering arguments: --filter-completed-before, --filter-completed-after:

	        dsglobus --task-list --filter-completed-after 2021-02-01 --filter-completed-before 2021-02-28
	        
	  - Delete files or directories on the NCAR RDA Quasar (rda-quasar) endpoint. Required
	    arguments: --delete, --endpoint, --target-file:

	        dsglobus --delete --endpoint rda-quasar --target-file /ds999.9/file.txt
	        
	  - Create a directory on an endpoint.  Required arguments: --mkdir, --endpoint, 
	    --path:

	        dsglobus --mkdir --endpoint rda-quasar --path /ds999.9/new_path/
	        
	  - Rename a file or directory on an endpoint.  Required arguments: --rename, 
	    --endpoint, --oldpath, --newpath:

	        dsglobus --rename --endpoint rda-quasar --oldpath /ds999.9/oldfile.txt --newpath /ds999.9/newfile.txt
	        
	  - Cancel a transfer task.  Required arguments: --cancel-task, --task-id:

	        dsglobus --cancel-task --task-id <TASK_ID>
	  
	======================================================================================
	Filtering:
	    When using the --filter option with --list-files, you can list files and dirs on a 
	    specific path on an endpoint based on the filter criterion.
	    
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

	======================================================================================
	Valid RDA endpoint names:
	    NCAR RDA GLADE: 'rda-glade'
	    NCAR RDA Quasar: 'rda-quasar'
	    NCAR RDA Quasar DRDATA: 'rda-quasar-drdata'

	======================================================================================
	Path values:
	    When using the --path, --oldpath, --newpath, or --target-file arguments, the path
	    given is relative to the host path on the specified endpoint.  
	    
	    For example, the host path on the 'NCAR RDA GLADE' endpoint is 
	    /glade/campaign/collections/rda/, therefore any file operation to/from this endpoint must 
	    be specified relative to this host path.  To retrieve a listing of files stored
	    under /glade/campaign/collections/rda/data/ds540.0/, specify the relative path of 
	    /data/ds540.0/:
	    
	        dsglobus --list-files --endpoint 'rda-glade' --path /data/ds540.0/
	    
	    Host paths on RDA shared endpoints: 
	        NCAR RDA GLADE: /glade/campaign/collections/rda/
	        NCAR RDA Quasar: /gpfs/gpfs0/archive/rda/
	        NCAR RDA Quasar DRDATA: /gpfs/gpfs0/archive/rda_dr/

	======================================================================================
	Transferring multiple files (JSON input):
	    Multiple files can be transferred in a single call using JSON formatted input.  
	    Required fields in the JSON input are 'action' (set to 'transfer'), 
	    'source_endpoint', 'destination_endpoint', and 'files', specified as an array of
	    JSON objects with 'source_file', and 'destination_file' key-value pairs.  The 
	    fields 'label' and 'verify_checksum' are optional.  JSON input can be passed into 
	    dsglobus in one of the following ways:
	    
	    1. dsglobus < files.json
	    2. cat files.json | dsglobus
	    3. dsglobus << EOF
	       {
	         <JSON formatted input>
	       }
	       EOF
	       
	    Example JSON input:
	    {
	      "action": "transfer",
	      "source_endpoint": "rda-glade",
	      "destination_endpoint": "rda-quasar",
	      "label": "RDA Quasar transfer",
	      "verify_checksum": True,
	      "files": [
	         {"source_file": "/data/ds999.9/file1.tar", "destination_file": "/ds999.9/file1.tar"},
	         {"source_file": "/data/ds999.9/file2.tar", "destination_file": "/ds999.9/file2.tar"},
	         {"source_file": "/data/ds999.9/file3.tar", "destination_file": "/ds999.9/file3.tar"}
	      ]
	    }
	''')
	
	parser = argparse.ArgumentParser(prog='dsglobus', formatter_class=argparse.RawDescriptionHelpFormatter, description=desc, epilog=textwrap.dedent(epilog))

	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('--list-files', '-ls', action="store_true", default=False, help='List files on a specified endpoint path.')
	group.add_argument('--transfer', '-t', action="store_true", default=False, help='Transfer data between RDA endpoints.')
	group.add_argument('--get-task', '-gt', action="store_true", default=False, help='Show information about a Globus task.')
	group.add_argument('--task-list', '-tl', action="store_true", default=False, help='List Globus tasks for the current user.')
	group.add_argument('--delete', '-d', action="store_true", default=False, help='Delete files and/or directories on an endpoint.')
	group.add_argument('--mkdir', action="store_true", default=False, help='Create a directory on an endpoint.')
	group.add_argument('--rename', action="store_true", default=False, help='Rename a file or directory on an endpoint.')
	group.add_argument('--cancel-task', '-ct', action="store_true", default=False, help='Cancel a Globus task.')
	
	parser.add_argument('--endpoint', '-ep', action="store", dest="ENDPOINT", help='Endpoint ID or name.  Required with --list-files and --delete arguments.')
	parser.add_argument('--source-endpoint', '-se', action="store", dest="SOURCE_ENDPOINT", help='Source endpoint ID or name.  Required with --transfer option.')
	parser.add_argument('--destination-endpoint', '-de', action="store", dest="DESTINATION_ENDPOINT", help='Destination endpoint ID or name.  Required with --transfer.')
	parser.add_argument('--source-file', '-sf', action="store", dest="SOURCE_FILE", help='Path to source file name, relative to source endpoint host path.  Required with --transfer option.')
	parser.add_argument('--destination-file', '-df', action="store", dest="DESTINATION_FILE", help='Path to destination file name, relative to destination endpoint host path.  Required with --transfer.')
	parser.add_argument('--verify-checksum', '-vc', action="store_true", default=False, help='Verify checksum after transfer.  Use with the --transfer action.  Default = False.')
	parser.add_argument('--target-file', '-tf', action="store", dest="TARGET_FILE", help='Path to target file name, relative to endpoint host path.  Required with --delete.')
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
	parser.add_argument('--oldpath', action="store", dest="OLDPATH", help='Name of existing file or directory, including path.  Required with --rename argument.')
	parser.add_argument('--newpath', action="store", dest="NEWPATH", help='Name of new file or directory, including path.  Required with --rename argument.')
	
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)
	
	args = parser.parse_args(sys.argv[1:])
	my_logger.info("[parse_input] Input command & arguments: {0}: {1}".format(sys.argv[0], args))	

	opts = vars(args)
	if args.list_files:
		opts.update({"action": "ls"})
	if args.transfer:
		opts.update({"action": "transfer"})
	if args.get_task:
		opts.update({"action": "gt"})
	if args.task_list:
		opts.update({"action": "tl"})
	if args.delete:
		opts.update({"action": "delete"})
	if args.mkdir:
		opts.update({"action": "mkdir"})
	if args.rename:
		opts.update({"action": "rename"})
	if args.cancel_task:
		opts.update({"action": "cancel"})
		
	if args.get_task and args.TASK_ID is None:
		msg = "Option --get-task requires --task-id."
		my_logger.error(msg)
		parser.error(msg)
	if args.transfer and (args.SOURCE_ENDPOINT is None or args.DESTINATION_ENDPOINT is None or args.SOURCE_FILE is None or args.DESTINATION_FILE is None):
		msg = "Option --transfer requires arguments [--source-endpoint, --destination-endpoint, --source-file, --destination-file]."
		my_logger.error(msg)
		parser.error(msg)
	if args.delete and (args.ENDPOINT is None or args.TARGET_FILE is None):
		msg = "Option --delete requires --endpoint."
		my_logger.error(msg)
		parser.error(msg)
	if args.list_files and (args.ENDPOINT is None or args.PATH is None):
		msg = "Option --list-files requires both --endpoint and --directory."
		my_logger.error(msg)
		parser.error(msg)
	if args.mkdir and (args.ENDPOINT is None or args.PATH is None):
		msg = "Option mkdir (--mkdir) requires both --endpoint and --path."
		my_logger.error(msg)
		parser.error(msg)
	if args.rename and (args.OLDPATH is None or args.NEWPATH is None or args.ENDPOINT is None):
		msg = "Option rename (--rename) requires endpoint name (--endpoint), old path (--oldpath), and new path (--newpath)."
		my_logger.error(msg)
		parser.error(msg)
	if args.cancel_task and (args.TASK_ID is None):
		msg = "Option --cancel-task requires --task-id."
		my_logger.error(msg)
		parser.error(msg)

	if args.list_files:
		pass
	elif args.transfer:
		opts.update({"files": [{"source_file": args.SOURCE_FILE, "destination_file": args.DESTINATION_FILE}]})
	elif args.delete:
		opts.update({"files": [args.TARGET_FILE]})
	elif args.get_task:
		pass
	elif args.task_list:
		pass
	elif args.mkdir:
		pass
	elif args.rename:
		opts.update({"files": [{"old_path": args.OLDPATH, "new_path": args.NEWPATH}]})
	elif args.cancel_task:
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

	# write to different log file if user = apache
	if (pwd.getpwuid(os.getuid())[0] == 'apache'):
		LOGFILE = 'dsglobus.apache.log'
	else:
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
def colon_formatted_print(data, named_fields):
	maxlen = max(len(n) for n, f in named_fields) + 1
	for name, field in named_fields:
		field_keyfunc = _key_to_keyfunc(field)
		print("{} {}".format((name + ":").ljust(maxlen), field_keyfunc(data)))
        
#=========================================================================================
""" Set up logging """
my_logger = logging.getLogger(__name__)
console_logger = logging.getLogger('console')
configure_log(level='info')

if __name__ == "__main__":
	from_pipe = not os.isatty(sys.stdin.fileno())
	if from_pipe:
		from_pipe = select.select([sys.stdin,],[],[],0.0)[0]
		if len(sys.argv) > 1:
			main()
		elif from_pipe:
			json_input = read_json_from_stdin()
			main(json_input=json_input)
	else:
		main()
