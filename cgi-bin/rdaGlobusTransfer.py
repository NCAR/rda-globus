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
import urllib
from Cookie import SimpleCookie
from MyGlobus import headers, MyGlobus
from globus_sdk import TransferClient, TransferData
from PyDBI import myget
from phpserialize import *
import json

def main():
    print "Content-type: text/html\r\n\r\n"
    form = cgi.FieldStorage()

    """ Print HTTP headers and debug info """
    #print_info(form)
    
    if("action" in form):
    	if(form["action"] == "display_status"):
    		try:
    			task_id = form["task_id"]
    			transfer_status(task_id)
    		except:
    			print "<div id=\"error\">\n"
    			print "<p>Error: task ID missing from URL query.  Please contact rdahelp@ucar.edu for assistance.</p>\n"
    			print "</div>\n"
    	else:
    		submit_transfer(form)

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
    if(gtype == '1'):
       source_endpoint_id = MyGlobus['data_request_ep']
    if(gtype == '3'):
       source_endpoint_id = MyGlobus['datashare_ep']

    destination_endpoint_id = form['endpoint_id'].value

    """ Instantiate the Globus SDK transfer client """
    transfer = TransferClient()
        
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

    #transfer.endpoint_autoactivate(source_endpoint_id)
    #transfer.endpoint_autoactivate(destination_endpoint_id)
    
    task_id = transfer.submit_transfer(transfer_data)['task_id']
    transfer_status(task_id)
    
    return
    
def transfer_status(task_id):
    """
    Call the Globus Transfer API to get status/details of transfer with the given
    task_id.
    """
    transfer = TransferClient()
    task = transfer.get_task(task_id)
    
    """ Display transfer status """
    print "<div id=\"transferStatusHeader\">\n<h1>Transfer status</h1>\n</div>"
    print "<p>\n<strong>Task ID</strong>: {0}<br />\n".format(task["task_id"])
    print "<strong>Source endpoint</strong>: {0}<br />\n".format(task["source_endpoint_display_name"])
    print "<strong>Destination Endpoint</strong>: {0}<br />\n".format(task["destination_endpoint_display_name"])
    print "<strong>Request Time</strong>: {0}<br />\n".format(task["request_time"])
    print "<strong>Status</strong>: {0}<br />\n".format(task["status"])
    print "<strong>Files transferred</strong>: {0}<br />\n".format(task["files_transferred"])
    print "<strong>Faults</strong>: {0}\n</p>\n".format(task["faults"])
    
    print "<div>\n"
    print "<a href=\"/#!cgi-bin/rdaGlobusTransfer?method=POST&action=display_status&task_id={0}\">\n".format(task["task_id"])
    print "<button>Refresh</button>\n"
    print "</a>\n"
    print "</div>\n"

    return

def get_session_data():
    """ 
    - Retrieve session data from RDADB
    """
    sid = SimpleCookie(os.environ['HTTP_COOKIE'])['PHPSESSID'].value
    keys = ['id','access','data']
    condition = " WHERE {0} = '{1}'".format("id", sid)
    myrec = myget('sessions', keys, condition)
    
    """ Raise exception if myrec is nonempty """

    """ Return unserialized session data """
    return unserialize(myrec['data'])

def set_environ():
    """ Define environment variables required by this script """
    os.environ['REQUEST_METHOD'] = 'POST'
    os.environ['GLOBUS_SDK_TRANSFER_TOKEN'] = MyGlobus['transfer_token']
    os.environ['GLOBUS_SDK_AUTH_TOKEN'] = MyGlobus['auth_token']
    
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
    print_directory()
    print_arguments()
    print_form(form)
    print_session_data()
    print_environ()

#=========================================================================================

if __name__ == "__main__":
    set_environ()
    main()