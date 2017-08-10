#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
##################################################################################
#     Title : rdaGlobusTransfer.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 11/09/2016
#   Purpose : Python cgi script to submit Globus data transfers on behalf of RDA users.
#
# Work File : rda-web-prod.ucar.edu:/data/web/cgi-bin/rdaGlobusTransfer*
# Test File : rda-web-dev.ucar.edu:/data/web/cgi-bin/rdaGlobusTransfer_test*
##################################################################################

import os, sys

sys.path.append("/glade/u/home/rdadata/lib/python")
sys.path.append("/glade/u/home/tcram/lib/python")

import cgi, cgitb
from Cookie import SimpleCookie
from phpserialize import *
import json
import hmac
from base64 import b64encode
import hashlib
import requests

from MyGlobus import headers, MyGlobus
from PyDBI import myget, myupdt
from globus_utils import load_app_client
from globus_sdk import (TransferClient, TransferAPIError,
                        TransferData, RefreshTokenAuthorizer)
from dsglobus import *

try:
    from urllib.parse import urlencode
except:
    from urllib import urlencode

def main():
    form = cgi.FieldStorage()

    """ Print HTTP headers and debug info """
    print_info(form)
    
    if 'endpoint_id' in form:
    	browsecallback(form)
    elif 'action' in form:
    	try:
    		task_id = form.getvalue('task_id')
    		action = form.getvalue('action')
    		if (action == 'transfer_status'):
    			transfer_status(task_id)
    		elif (action == 'display_status'):
    			new = False
    			if ('new' in form and form.getvalue('new') == 'true'):
    				new = True
    			display_transfer_status(task_id, new=new)
    	except:
    		print_header()
    		print "<div id=\"error\">\n"
    		print "<p>Error: task ID missing from URL query.  Please contact rdahelp@ucar.edu for assistance.</p>\n"
    		print "</div>\n"
    else:
    	authcallback(form)

def authcallback(form):
    """Handles the interaction with Globus Auth."""

    # If we're coming back from Globus Auth in an error state, the error
    # will be in the "error" query string parameter.
    if 'error' in form:
        print_header()
        print "<p><strong>You could not be logged into the portal:</strong>{0} {1}\n".format(form['error_description'].value,form['error'].value)
        return

    # Set up our Globus Auth client
    client = load_app_client()
    redirect_uri = 'https://' + os.environ['HTTP_HOST'] + MyGlobus['redirect_uri']
    state = generate_state_parameter(MyGlobus['client_id'], MyGlobus['private_key'])
    client.oauth2_start_flow(redirect_uri, state=state, refresh_tokens=True)

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    if 'code' not in form:
        auth_uri = client.oauth2_get_authorize_url()
        print "Location: {0}\r\n".format(auth_uri)
    else:
        # If we do have a "code" param, we're coming back from Globus Auth
        # and can start the process of exchanging an auth code for a token.        
        code = form.getvalue('code')
        tokens = client.oauth2_exchange_code_for_tokens(code)

        if not is_valid_state(tokens['state']):
        	print_http_status("403 Forbidden")
        	sys.exit()

        #id_token = tokens.decode_id_token(client)
        tokens=tokens.by_resource_server
        update_session_data(tokens)

        transfer(form)
        
        return

def transfer(form):
    """
    - Send user to Globus to select a destination endpoint using the
      Browse Endpoint helper page.
    - Assumes the submitted form has been saved to the session.
    """    
    protocol = 'https://'
    session = get_session_data()
    cancelurl = session['cancelurl']
    
    params = {
    	'method': 'POST',
        'action': protocol + os.environ['HTTP_HOST'] + MyGlobus['redirect_uri'],
        'filelimit': 0,
        'folderlimit': 1,
        'cancelurl': cancelurl,
        'label': 'NCAR RDA Globus transfer'
    }

    browse_endpoint = 'https://www.globus.org/app/browse-endpoint?{}'.format(urlencode(params))
    print "Location: {0}\r\n\r\n".format(browse_endpoint)

    return

def browsecallback(form):
	""" Handles the interaction with the Browse Endpoint helper page API """

	session = get_session_data()
	
	if session['dsrqst']:
		submit_request(session, form)
	else:
		submit_transfer(session, form)
	
	return

def submit_transfer(session, form):
    """
    - Take the data returned by the Browse Endpoint helper page
      and make a Globus transfer request.
    - Send the user to the transfer status page with the task id
      from the transfer.
    - Input argument 'session' is the user's session data retrieved from the
      sessions DB table
    """

    email = session['email']
    gtype = session['gtype']
    dsid = session['dsid']
    directory = session['directory']
    selected = session['files']
    
    """ Trim leading '/data/' from web directory. """
    if(directory.find('/data/',0,6) == 0):
        directory = directory.replace('/data/','',1)
    
    """ Define source endpoint ID and paths """
    host_endpoint = MyGlobus['host_endpoint_id']
    
    if(gtype == '1'):
       source_endpoint_id = MyGlobus['data_request_ep']
    if(gtype == '3'):
       source_endpoint_id = MyGlobus['datashare_ep']

    destination_endpoint_id = form.getvalue('endpoint_id')

    """ Check if user has a share set up for this endpoint & path """
    share_data = {'email': email, 'dsid': dsid, 'notify': True}
    if not query_acl_rule(2, share_data):
        data = add_endpoint_acl_rule(2, share_data)
	
    """ Instantiate the Globus SDK transfer client """
    transfer = TransferClient(authorizer=RefreshTokenAuthorizer(
        session['transfer.api.globus.org']['refresh_token'], load_app_client()))
        
    """ Instantiate TransferData object """
    transfer_data = TransferData(transfer_client=transfer,
                                 source_endpoint=source_endpoint_id,
                                 destination_endpoint=destination_endpoint_id,
                                 label=form.getvalue('label'))

    """ Add files to be transferred.  Note source_path is relative to the source
        endpoint base path. """
    for file in selected:
        source_path = directory + selected[file]
        dest_path = form.getvalue('path') + selected[file]
        transfer_data.add_item(source_path, dest_path)

    transfer.endpoint_autoactivate(source_endpoint_id)
    transfer.endpoint_autoactivate(destination_endpoint_id)
    
    task_id = transfer.submit_transfer(transfer_data)['task_id']
    transfer_status(task_id, new=True)
    
    return
    
def transfer_status(task_id, new=False):
    """
    Call Globus to get status/details of transfer associated with the given task_id.
    """
    update_transfer_status(task_id)
    
    params = {'method': 'POST', 'action': 'display_status', 'task_id': task_id}
    if new:
    	params.update({'new': 'true'})
    display_status = 'https://' + os.environ['HTTP_HOST'] + '/#!cgi-bin/rdaGlobusTransfer?'
    qs = urlencode(params)
    print "Location: %s%s\r\n" % (display_status, qs)

def update_transfer_status(task_id):
    """ Update the Globus transfer status in the database """

    """ Get session data from database """
    session = get_session_data()

    """ Instantiate the transfer client & get transfer task details """
    transfer = TransferClient(authorizer=RefreshTokenAuthorizer(
        session['transfer.api.globus.org']['refresh_token'], 
        load_app_client()))
    task = transfer.get_task(task_id)
    
    task_data = {'task_id': task_id,
                 'source_endpoint_display_name': task['source_endpoint_display_name'],
                 'destination_endpoint_display_name': task['destination_endpoint_display_name'],
                 'request_time': task['request_time'],
                 'status': task['status'],
                 'files_transferred': task['files_transferred'],
                 'faults': task['faults']}
                 
    update_session_data(task_data)
    return
    
def display_transfer_status(task_id, new=False):
    """ Display Globus transfer status """
    session = get_session_data()

    source_endpoint_display_name = session['source_endpoint_display_name']
    destination_endpoint_display_name = session['destination_endpoint_display_name']
    request_time = session['request_time']
    status = session['status']
    files_transferred = session['files_transferred']
    faults = session['faults']
    dsid = session['dsid']
    
    detail_uri = "https://www.globus.org/app/activity/{0}".format(task_id)
    
    protocol = 'https://'
    redirect_uri = protocol + os.environ['HTTP_HOST'] + MyGlobus['redirect_uri']
    
    print_header()
    print "<script id=\"globus_script\" language=\"JavaScript\" type=\"text/javascript\" src=\"/js/rda_globus.js\"></script>\n"
    print "<form name=\"displayStatus\" action=\"{0}\" method=\"POST\" onsubmit=\"showLoading()\">\n".format(redirect_uri)
    print"<input type = \"hidden\" name=\"method\" value=\"POST\">\n"
    print"<input type = \"hidden\" name=\"action\" value=\"transfer_status\">\n"
    print"<input type = \"hidden\" name=\"task_id\" value=\"{0}\">\n".format(task_id)
    if new:
    	print "<div class=\"alert alert-success\" id=\"alertMessage\">\n"
    	print "Transfer request submitted successfully. Task ID: <a href=\"{0}\" class=\"alert-link\" target=\"_blank\">{1}</a>".format(detail_uri, task_id)
    	print "</div>"
    print "<div id=\"transferStatusHeader\" style=\"margin-left: 10px\">\n"
    print "<h1>Globus transfer details</h1>\n"
    print "</div>"
    print "<hr style=\"height: 1px; color: #cccccc; background-color: #cccccc; border: none; width: 90%;\">"
    print "<div id=\"transferDetails\" style=\"margin-left: 10px\">\n"
    print "<p>\n"
    print "<strong>Task ID</strong>: {0}<br />\n".format(task_id)
    print "<strong>Source endpoint</strong>: {0}<br />\n".format(source_endpoint_display_name)
    print "<strong>Destination Endpoint</strong>: {0}<br />\n".format(destination_endpoint_display_name)
    print "<strong>Request Time</strong>: {0}<br />\n".format(request_time)
    print "<strong>Status</strong>: {0}<br />\n".format(status)
    print "<strong>Files transferred</strong>: {0}<br />\n".format(files_transferred)
    print "<strong>Faults</strong>: {0}<br />\n".format(faults)
    print "<strong>Overview and event log</strong>: <a href=\"{0}\" target=\"_blank\">{1}</a></p>\n".format(detail_uri, detail_uri)
    print "</div>\n"
    print "<div style=\"margin-left: 10px\">\n"
    print "<p><button type=\"submit\" class=\"btn btn-primary\">Refresh</button></p>\n"
    print "<p><a href=\"/datasets/{0}\">Return to the {1} dataset page</a>\n</p>\n".format(dsid, dsid)
    print "</div>\n"
    
def submit_request(session, form):
	""" Submit request parameters to dsrqst.php and display request message """
	sid = SimpleCookie(os.environ['HTTP_COOKIE'])['PHPSESSID'].value
	endpoint_id = form.getvalue('endpoint_id')
	dest_path = form.getvalue('path')
	data = {
		'endpoint_id': endpoint_id, 
		'dest_path': dest_path,
		'label': form.getvalue('label')
	}
	update_session_data(data)
		
	""" split rqstParams into Python dict key-value pairs """
	params = dict(x.split('=') for x in session['rqstParams'].split('&'))
	params.update({'method': 'POST',
				'globus': 'Y',
				'sid': sid,
				'endpoint_id': endpoint_id,
				'dest_path': dest_path
		        })

	redirect_uri = "https://{0}/php/dsrqst.php".format(os.environ['HTTP_HOST'])
	r = requests.post(redirect_uri, data=params)
	if (r.status_code == requests.codes.ok):
		display_request_message(r, params['dsid'])
	
	return

def display_request_message(response, dsid):
	""" Display content returned by dsrqst.php """
	
	print_header()
	print "<script id=\"globus_script\" language=\"JavaScript\" type=\"text/javascript\" src=\"/js/rda_globus.js\"></script>\n"
	print "<div id=\"requestDetails\" style=\"margin-left: 10px\">\n"
	print "{0}\n".format(response.text)
	print "</div>\n"
	print "<div style=\"margin-left: 10px\">\n"
	print "<p><a href=\"/datasets/{0}\">Return to the {1} dataset page</a>\n</p>\n".format(dsid, dsid)
	print "</div>\n"

def get_session_data():
    """ 
    - Retrieve session data from RDADB.
    """
    sid = SimpleCookie(os.environ['HTTP_COOKIE'])['PHPSESSID'].value
    keys = ['id','access','data']
    condition = " WHERE {0} = '{1}'".format("id", sid)
    myrec = myget('sessions', keys, condition)
    
    """ Raise exception if myrec is nonempty """

    """ Return unserialized session data """
    return unserialize(myrec['data'])

def update_session_data(data):
    """ 
    - Update session data in RDADB
    """
    sid = SimpleCookie(os.environ['HTTP_COOKIE'])['PHPSESSID'].value
    keys = ['id','access','data']
    condition = " WHERE {0} = '{1}'".format("id", sid)
    myrec = myget('sessions', keys, condition)
    
    session_data = unserialize(myrec['data'])
    session_data.update(data)
    
    """ Update session """
    myupdt('sessions', {'data': serialize(session_data)}, condition)
    
    return

def set_environ():
    """ Define environment variables required by this script """
    os.environ['REQUEST_METHOD'] = 'POST'
    os.environ['GLOBUS_SDK_TRANSFER_TOKEN'] = MyGlobus['transfer_token']
    os.environ['GLOBUS_SDK_AUTH_TOKEN'] = MyGlobus['auth_token']
    
    return

def get_protocol():
    """ Return the web server protocol """
    server_protocol = os.environ['SERVER_PROTOCOL']
    server_port = os.environ['SERVER_PORT']
    
    if(server_protocol.find('HTTPS') != -1 and server_protocol != 'off' or server_port == '443'):
        protocol = 'https://'
    else:
    	protocol = 'http://'

    return protocol

def print_header():
    print "Content-type: text/html\r\n\r\n"
    return

def print_http_status(msg):
    print "Status: " + msg + "\r\n\r\n"
    return

def generate_state_parameter(client_id, private_key):
	""" Generate a state parameter for OAuth2 requests """
	sid = SimpleCookie(os.environ['HTTP_COOKIE'])['PHPSESSID'].value
	raw_state = sid + client_id
	hashed = hmac.new(private_key, raw_state, hashlib.sha1)
	state = b64encode(hashed.digest())
	return (state)

def is_valid_state(state):
	""" Validate the OAuth2 state parameter """
	recreated_state = generate_state_parameter(MyGlobus['client_id'], MyGlobus['private_key'])
	if state == recreated_state:
		return True
	else:
		return False

# Test/debug code
# ===============

def print_environ(environ=os.environ):
    """Dump the shell environment as HTML."""
    keys = environ.keys()
    keys.sort()
    print
    print "<h3>Shell Environment:</h3>"
    print "<dl>"
    for key in keys:
        print "<dt>", escape(key), "<dd>", escape(environ[key])
    print "</dl>"
    print

def print_form(form):
    keys = form.keys()
    keys.sort()
    print
    print "<h3>Form Contents:</h3>"
    if not keys:
        print "<p>No form fields."
    print "<dl>"
    for key in keys:
        print "<dt>" + escape(key) + ":",
        value = form[key]
        print "<i>" + escape(repr(type(value))) + "</i>"
        print "<dd>" + escape(repr(value))
    print "</dl>"
    print

def print_directory():
    """Dump the current directory as HTML."""
    print
    print "<h3>Current Working Directory:</h3>"
    try:
        pwd = os.getcwd()
    except os.error, msg:
        print "os.error:", escape(str(msg))
    else:
        print escape(pwd)
    print

def print_arguments():
    print
    print "<h3>Command Line Arguments:</h3>"
    print
    print sys.argv
    print

def escape(s, quote=None):
    """
    Replace special characters "&", "<" and ">" to HTML-safe sequences.
    If the optional flag quote is true, the quotation mark character (")
    is also translated.
    """
    s = s.replace("&", "&amp;") # Must be done first!
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    if quote:
        s = s.replace('"', "&quot;")
    return s

def print_session_data():
    """ Print session data """
    session = get_session_data()
    print "<p>\n<h3>Session data:</h3>\n</p>\n"
    print "<p>\n"
    print_dict(session)
    print "</p>\n"

def print_dict(mydict):
    """ Print contents of a dictionary """
    print "<dl>\n"
    for key, val in mydict.iteritems():
        if isinstance(val, dict):
            print "<dt><strong>{0} :</strong> <dd>".format(key)
            print_dict(val)
        else:
            print "<dt><strong>{0} :</strong> <dd>{1}".format(key, val)
    print "</dl>\n"

def print_info(form):
    """ Print debug info """
    print_header()
    print_directory()
    print_arguments()
    print_form(form)
   # print_session_data()
    print_environ()
    sys.exit()

#=========================================================================================

if __name__ == "__main__":
    set_environ()
    main()