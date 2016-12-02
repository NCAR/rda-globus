#!/usr/bin/env python
#
##################################################################################
#     Title : globusSdkTest.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 11/09/2016
#   Purpose : Script to test the functionality of the Globus SDK client.
#
# Work File : rda-web-prod.ucar.edu:/data/web/cgi-bin/rdaGlobusTransfer*
# Test File : rda-web-dev.ucar.edu:/data/web/cgi-bin/rdaGlobusTransfer_test*
##################################################################################

import os, sys

sys.path.append("/glade/u/apps/contrib/modulefiles/globus-sdk")
sys.path.append("/glade/u/home/rdadata/lib/python")
sys.path.append("/glade/u/home/tcram/lib/python")

from MyGlobus import headers, MyGlobus
from globus_sdk import TransferClient, TransferData

def main():
    task_id = submit_transfer()
    print "Transfer submitted.  Task ID: {0}\n".format(task_id)
    #content = transfer_status(task_id)

def submit_transfer():
    """
    - Take the data returned by the Browse Endpoint helper page
      and make a Globus transfer request.
    - Send the user to the transfer status page with the task id
      from the transfer.
    """

    """ Define list of files to transfer """
    selected = {
        0: "RCPP/2020_2030/qfx/qfx_RCPP_2020_01.nc",
        1: "RCPP/2020_2030/qfx/qfx_RCPP_2020_02.nc",
        2: "RCPP/2020_2030/qfx/qfx_RCPP_2020_03.nc",
        3: "RCPP/2020_2030/qfx/qfx_RCPP_2020_04.nc",
        4: "RCPP/2020_2030/qfx/qfx_RCPP_2020_05.nc"
    }
    
    """ Define source endpoint ID and paths """
    source_endpoint_id = MyGlobus['datashare_ep']
    source_endpoint_base = MyGlobus['datashare_ep_base']

    """ Instantiate the Globus SDK transfer client """
    transfer = TransferClient()
    
    destination_endpoint_id = 'd33b3614-6d04-11e5-ba46-22000b92c6ec'
    source_path = source_endpoint_base + '/ds601.0/'
        
    """ Instantiate TransferData object """
    transfer_data = TransferData(transfer_client=transfer,
                                 source_endpoint=source_endpoint_id,
                                 destination_endpoint=destination_endpoint_id,
                                 label='Globus SDK test transfer')

    for file in selected:
        dest_path = '/glade/p/rda/work/tcram/globus/browse_endpoint_test/' + selected[file]
        
        transfer_data.add_item(source_path=source_path,
                               destination_path=dest_path,
                               recursive=True)
    """
    transfer.endpoint_autoactivate(source_endpoint_id)
    transfer.endpoint_autoactivate(destination_endpoint_id)
    task_id = transfer.submit_transfer(transfer_data)['task_id']
    """
    
    task_id = 'None (test)'
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

def set_environ():
    """ Define environment variables required by this script """
    os.environ['REQUEST_METHOD'] = 'POST'
    os.environ['GLOBUS_SDK_TRANSFER_TOKEN'] = MyGlobus['transfer_token']
    os.environ['GLOBUS_SDK_AUTH_TOKEN'] = MyGlobus['auth_token']
    
    return

#=========================================================================================

if __name__ == "__main__":
    set_environ()
    main()