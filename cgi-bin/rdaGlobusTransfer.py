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
from globus_sdk import TransferClient
from PyDBI import myget

def main():
    print "Content-type: text/html\r\n\r\n"
    content = list_environ()
    print content

    task_id = submit_transfer()
    #content = transfer_status(task_id)

def list_environ():
    content = "<p>\n<strong>Environment:</strong>\n</p>\n"
    for param in os.environ.keys():
      content += "<b>{0}</b>: {1}<br />".format(param, os.environ[param])
    
    return content


def submit_transfer():
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

    print "<p>\n<strong>Session data:</strong>\n</p>\n"
    print "<p>\n"
    print "ID: {0}<br />\nAccess: {1}<br />\nData: {2}<br />\n".format(myrec['id'],myrec['access'],myrec['data'])
    print "</p>\n"

    gtype = 3
        
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
    
    # Read POST data
    form = cgi.FieldStorage(environ={'REQUEST_METHOD':'POST'})
    
    print "<p><strong>Keys: </strong></p>\n"
    print "<p>{0}</p>\n".format(form.keys())

    if "endpoint_id" not in form or "folder[0]" not in form:
       print "<strong>Error</strong>:"
       print "Endpoint ID and/or destination folder missing from submitted form."
       return

    destination_endpoint_id = form.getvalue("endpoint_id","(endpoint ID missing)")
    destination_folder = form.getvalue("folder[0]", "(destination folder missing)")
    
    print "<p><strong>POST data:</strong></p>\n"
    print "<p>\n"
    print "Endpoint ID: {0}<br />\nDestination folder: {1}\n".format(destination_endpoint_id, destination_folder)
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

#=========================================================================================

if __name__ == "__main__":
    main()