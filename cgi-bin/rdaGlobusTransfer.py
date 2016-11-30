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
from globus_sdk import TransferClient
from PyDBI import myget

def main():
    print "Content-type: text/html\r\n\r\n"
    form = cgi.FieldStorage()

    print_directory()
    print_arguments()
    print_form(form)
    print_environ()

    #task_id = submit_transfer(form)
    #content = transfer_status(task_id)

def submit_transfer(form):
    """
    - Take the data returned by the Browse Endpoint helper page
      and make a Globus transfer request.
    - Send the user to the transfer status page with the task id
      from the transfer.
    """
    # Get session ID and session data from database
    
    sid = SimpleCookie(os.environ['HTTP_COOKIE'])['PHPSESSID'].value
    keys = ['id','access','data']
    condition = " WHERE {0} = '{1}'".format("id", sid)
    myrec = myget('sessions', keys, condition)
    
    # check if myrec is nonempty
    
    print "<p>\n<strong>Session data:</strong>\n</p>\n"
    print "<p>\n"
    print "ID: {0}<br />\nAccess: {1}<br />\nData: {2}<br />\n".format(myrec['id'],myrec['access'],myrec['data'])
    print "</p>\n"

    """
    # extract query parameters from HTTP_REFERER
    GET = {}
    ref = os.environ['HTTP_REFERER']
    query_idx = ref.index('?')
    query_args = ref[query_idx+1:].split('&')
    print "<p>\n"
    for arg in query_args:
        t = arg.split('=')
        if len(t) > 1:
            key,val = arg.split('=')
            GET[key] = urllib.unquote(val)
            print "{0}: {1}<br />".format(key,GET[key])

    gtype = 3
    """ 
    """    
    gtype = session['gtype']
    selected = session['files']
    dsid = session['dsid']
    directory = session['directory']
    
    tc = TransferClient()
    """

    # Define endpoint IDs and paths
    if(gtype == 3):
       source_endpoint_id = MyGlobus['datashare_ep']
       source_endpoint_base = MyGlobus['datashare_ep_base']
    if(gtype == 1):
       source_endpoint_id = MyGlobus['data_request_ep']
       source_endpoint_base = MyGlobus['data_request_ep_base']
    
#    if "endpoint_id" not in form or "path" not in form:
#       print "<strong>Error</strong>:"
#       print "Endpoint ID and/or destination folder missing from submitted form."
#       return

#    destination_endpoint_id = GET['endpoint_id']
#    destination_path = GET['path']
    
    print "<p><strong>Form contents:</strong></p>\n"
    print "<p>\n"
    print "Endpoint ID: {0}<br />\nDestination path: {1}\n".format(destination_endpoint_id, destination_path)
    print "</p>\n"
    
    task_id = 'task_id'
    return task_id
    
def transfer_status(task_id):
    """
    Call Globus to get status/details of transfer with
    task_id.

    The target template (tranfer_status.jinja2) expects a Transfer API
    'task' object.

    'task_id' is passed to the route in the URL as 'task_id'.
    """
    transfer = TransferClient(authorizer=RefreshTokenAuthorizer(
        session['tokens']['transfer.api.globus.org']['refresh_token'],
        load_portal_client()))
    task = transfer.get_task(task_id)

    return render_template('transfer_status.jinja2', task=task)

def print_environ(environ=os.environ):
    """Dump the shell environment as HTML."""
    keys = environ.keys()
    keys.sort()
    print
    print "<H3>Shell Environment:</H3>"
    print "<DL>"
    for key in keys:
        print "<DT>", escape(key), "<DD>", escape(environ[key])
    print "</DL>"
    print

def print_form(form):
    keys = form.keys()
    keys.sort()
    print
    print "<H3>Form Contents:</H3>"
    if not keys:
        print "<P>No form fields."
    print "<DL>"
    for key in keys:
        print "<DT>" + escape(key) + ":",
        value = form[key]
        print "<i>" + escape(repr(type(value))) + "</i>"
        print "<DD>" + escape(repr(value))
    print "</DL>"
    print

def print_directory():
    """Dump the current directory as HTML."""
    print
    print "<H3>Current Working Directory:</H3>"
    try:
        pwd = os.getcwd()
    except os.error, msg:
        print "os.error:", escape(str(msg))
    else:
        print escape(pwd)
    print

def print_arguments():
    print
    print "<H3>Command Line Arguments:</H3>"
    print
    print sys.argv
    print

def escape(s, quote=None):
    '''Replace special characters "&", "<" and ">" to HTML-safe sequences.
    If the optional flag quote is true, the quotation mark character (")
    is also translated.'''
    s = s.replace("&", "&amp;") # Must be done first!
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    if quote:
        s = s.replace('"', "&quot;")
    return s

#=========================================================================================

if __name__ == "__main__":
    os.environ['REQUEST_METHOD'] = 'POST'
    main()