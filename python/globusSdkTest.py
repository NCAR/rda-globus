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
    print "[main] Transfer submitted.  Task ID: {0}\n".format(task_id)
    transfer_status(task_id)

def submit_transfer():
    """
    - Take the data returned by the Browse Endpoint helper page
      and make a Globus transfer request.
    - Send the user to the transfer status page with the task id
      from the transfer.
    """

    """ Define list of files to transfer """
    dsid = 'ds132.1'
    selected = {
        0: "ispdv3_tarfiles/1755_V329.tar.gz",
        1: "ispdv3_tarfiles/1756_V329.tar.gz",
        2: "ispdv3_tarfiles/1757_V329.tar.gz",
        3: "ispdv3_tarfiles/1758_V329.tar.gz",
        4: "ispdv3_tarfiles/1759_V329.tar.gz"
    }
    
    """ Define source endpoint ID and paths """
    source_endpoint_id = MyGlobus['datashare_ep']

    """ Instantiate the Globus SDK transfer client """
    transfer = TransferClient()
    
    # cisl-toulon
    #destination_endpoint_id = 'dabdcd87-6d04-11e5-ba46-22000b92c6ec'
    # NCAR GLADE (ncar#gridftp)
    destination_endpoint_id = 'd33b3614-6d04-11e5-ba46-22000b92c6ec'
        
    """ Instantiate TransferData object """
    transfer_data = TransferData(transfer_client=transfer,
                                 source_endpoint=source_endpoint_id,
                                 destination_endpoint=destination_endpoint_id,
                                 label='Globus SDK test transfer')

    for file in selected:
        source_path = dsid + '/' + selected[file]
        #dest_path = '/Users/tcram/globus/browse_endpoint_test/' + selected[file]
        dest_path = '/glade/p/rda/work/tcram/globus/browse_endpoint_test/' + selected[file]
        
        print "[submit_transfer] Source path: {0}".format(source_path)
        print "[submit_transfer] Dest path: {0}\n".format(dest_path)
        
        transfer_data.add_item(source_path, destination_path=dest_path)

    #transfer.endpoint_autoactivate(source_endpoint_id)
    #transfer.endpoint_autoactivate(destination_endpoint_id)
    task_id = transfer.submit_transfer(transfer_data)
    
    return task_id
    
def transfer_status(task_id):
    """
    Call Globus to get status/details of transfer with
    task_id.

    The target template (tranfer_status.jinja2) expects a Transfer API
    'task' object.

    'task_id' is passed to the route in the URL as 'task_id'.
    """
    
    "[transfer_status] Task ID: {0}\n".format(task_id)
    
    transfer = TransferClient()
    task = transfer.get_task(task_id)
    
    print "[transfer_status] Type(task): {0}\n".format(type(task))

    """ Display transfer status """
    """
    print "[transfer_status] Transfer in progress ...\n"
    print "[transfer_status] Task ID: {0}\n".format(task["task_id"])
    print "[transfer_status] Source endpoint: {0}\n".format(task["source_endpoint_display_name"])
    print "[transfer_status] Destination Endpoint: {0}\n".format(task["destination_endpoint_display_name"])
    print "[transfer_status] Request Time: {0}\n".format(task["request_time"])
    print "[transfer_status] Status: {0}\n".format(task["status"])
    print "[transfer_status] Files transferred: {0}\n".format(task["files_transferred"])
    print "[transfer_status] Faults: {0}\n".format(task["faults"])
    """
    
    return

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