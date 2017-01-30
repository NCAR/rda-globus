#!/usr/bin/env python
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

sys.path.append("/glade/u/apps/contrib/modulefiles/globus-sdk")
sys.path.append("/glade/u/home/rdadata/lib/python")
sys.path.append("/glade/u/home/tcram/lib/python")

import cgi, cgitb
from Cookie import SimpleCookie
from MyGlobus import headers, MyGlobus
from PyDBI import myget
from phpserialize import *
import json
import globus_sdk

try:
    from urllib.parse import urlencode
except:
    from urllib import urlencode

def main():
    form = cgi.FieldStorage()

    """ Print HTTP headers and debug info """
    #print_info(form)
    
    if("action" in form):
    	if(form["action"].value == "transfer_status"):
    		try:
    			task_id = form["task_id"].value
    			transfer_status(task_id)
    		except:
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

    # Set up our Globus Auth/OAuth2 state
    redirect_uri = 'http://rda.ucar.edu/#!cgi-bin/rdaGlobusTransfer'
    client = globus_sdk.ConfidentialAppAuthClient(MyGlobus['client_id'], MyGlobus['client_secret'])
    client.oauth2_start_flow(redirect_uri, refresh_tokens=True)

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    if 'code' not in form:
        auth_uri = client.oauth2_get_authorize_url()
        print "Location: {0}\r\n".format(auth_uri)
    else:
        # If we do have a "code" param, we're coming back from Globus Auth
        # and can start the process of exchanging an auth code for a token.
        code = form['code'].value
        tokens = client.oauth2_exchange_code_for_tokens(code)

        id_token = tokens.decode_id_token(client)
        tokens=tokens.by_resource_server
        update_session_data(tokens)

        submit_transfer(form)

def transfer(form):
    """
    - Send user to Globus to select a destination endpoint using the
      Browse Endpoint helper page.
    - Assumes the submitted form has been saved to the session.
    """
    protocol = get_protocol()    
    dsid = ("",form['dsid'].value)['dsid' not in form]
    
    if('cancelurl' not in form):
        cancelurl = protocol + os.environ['HTTP_HOST'] + "/datasets/" + dsid
    else:
        cancelurl = form['cancelurl'].value

    params = {
    	'method': 'POST',
        'action': protocol + os.environ['HTTP_HOST'] + "/#!cgi-bin/rdaGlobusTransfer",
        'filelimit': 0,
        'folderlimit': 1,
        'cancelurl': cancelurl,
        'label': 'NCAR RDA Globus transfer'
    }

    browse_endpoint = 'https://www.globus.org/app/browse-endpoint?{}'.format(urlencode(params))
    print "Location: {0}\r\n".format(browse_endpoint)

    return

def submit_transfer(form):
    """
    - Take the data returned by the Browse Endpoint helper page
      and make a Globus transfer request.
    - Send the user to the transfer status page with the task id
      from the transfer.
    """

    """ Get session data from database """
    session = get_session_data()
    
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

    destination_endpoint_id = form['endpoint_id'].value

    """ Instantiate the Globus SDK transfer client """
    transfer_authorizer = RefreshTokenAuthorizer(session['tokens']['transfer.api.globus.org']['refresh_token'])
    client = globus_sdk.ConfidentialAppAuthClient(MyGlobus['client_id'], MyGlobus['client_secret'])
    transfer = TransferClient(transfer_authorizer, client)
        
    """ Instantiate TransferData object """
    transfer_data = TransferData(transfer_client=transfer,
                                 source_endpoint=source_endpoint_id,
                                 destination_endpoint=destination_endpoint_id,
                                 label=form['label'].value)

    """ Add files to be transferred.  Note source_path is relative to the source
        endpoint base path. """
    for file in selected:
        source_path = directory + selected[file]
        dest_path = form['path'].value + selected[file]
        transfer_data.add_item(source_path, dest_path)

    transfer.endpoint_autoactivate(source_endpoint_id)
    transfer.endpoint_autoactivate(destination_endpoint_id)
    
    task_id = transfer.submit_transfer(transfer_data)['task_id']
    transfer_status(task_id)
    
    return
    
def transfer_status(task_id):
    """
    Call Globus to get status/details of transfer associated with the given task_id.
    """

    """ Get session data from database """
    session = get_session_data()

    """ Instantiate the transfer client & get transfer task details """
    transfer_authorizer = RefreshTokenAuthorizer(session['tokens']['transfer.api.globus.org']['refresh_token'])
    client = globus_sdk.ConfidentialAppAuthClient(MyGlobus['client_id'], MyGlobus['client_secret'])
    transfer = TransferClient(transfer_authorizer, client)
    task = transfer.get_task(task_id)
    
    """ Display transfer status """
    print_header()
    print "<div id=\"transferStatusHeader\" style=\"margin-left: 10px\">\n"
    print "<h1>Transfer status</h1>\n"
    print "</div>"
    print "<hr style=\"height: 1px; color: #cccccc; background-color: #cccccc; border: none; width: 90%;\">"
    print "<p style=\"margin-left: 10px\">\n"
    print "<strong>Task ID</strong>: {0}<br />\n".format(task["task_id"])
    print "<strong>Source endpoint</strong>: {0}<br />\n".format(task["source_endpoint_display_name"])
    print "<strong>Destination Endpoint</strong>: {0}<br />\n".format(task["destination_endpoint_display_name"])
    print "<strong>Request Time</strong>: {0}<br />\n".format(task["request_time"])
    print "<strong>Status</strong>: {0}<br />\n".format(task["status"])
    print "<strong>Files transferred</strong>: {0}<br />\n".format(task["files_transferred"])
    print "<strong>Faults</strong>: {0}\n</p>\n".format(task["faults"])
    
    print "<div style=\"margin-left: 10px\">\n"
    print "<p><a href=\"/#!cgi-bin/rdaGlobusTransfer?method=POST&action=transfer_status&task_id={0}\">\n".format(task_id)
    print "<button>Refresh</button>\n"
    print "</a></p>\n"
    print "</div>\n"

    return

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
    myupdt('sessions', serialize(session_data), condition)
    
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
    print_session_data()
    print_environ()

#=========================================================================================

if __name__ == "__main__":
    set_environ()
    main()