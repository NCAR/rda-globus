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

from __future__ import print_function
import os, sys
import cgi, cgitb
import MyGlobus
from globus_sdk import TransferClient

print "Content-Type: text/html\n\n"

task_id = submit_transfer()
content = transfer_status(task_id)

# Render html
print content

def submit_transfer():
    """
    - Take the data returned by the Browse Endpoint helper page
      and make a Globus transfer request.
    - Send the user to the transfer status page with the task id
      from the transfer.
    """
    # Get session data
    gtype = session['gtype']
    selected = session['files']
    dsid = session['dsid']
    directory = session['directory']
    
    tc = TransferClient()

    # Define endpoint IDs and paths
    if(gtype == 3):
       source_endpoint_id = MyGlobus['datashare_ep']
       source_endpoint_base = MyGlobus['datashare_ep_base']
    if(gtype == 1):
       source_endpoint_id = MyGlobus['data_request_ep']
       source_endpoint_base = MyGlobus['data_request_ep_base']
    
    # Read POST data
    form = cgi.FieldStorage()

    if "endpoint_id" not in form or "folder[0]" not in form:
       print "<strong>Error</strong>:"
       print "Endpoint ID and/or destination folder missing from form."
       return

    destination_endpoint_id = form.getvalue("endpoint_id","(endpoint ID missing)")
    destination_folder = form.getvalue("folder[0]", "(destination folder missing)")
    
    return(task_id)

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

