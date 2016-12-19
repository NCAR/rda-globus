#!/usr/bin/env python
#
##################################################################################
#
#     Title : MyGlobus.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 11/10/2016
#   Purpose : Python module for Globus endpoint management
#
# Work File : $DSSHOME/lib/python/MyGlobus.py*
# Test File : $DSSHOME/lib/python/MyGlobus_test.py*
#  SVN File : $HeadURL: https://subversion.ucar.edu/svndss/tcram/python/PyDBI.py $
#
##################################################################################

transfer_tokenf = open('/glade/u/home/rdadata/dssdb/tmp/.globus/globus.transfer-token', 'r')
transfer_token = transfer_tokenf.read().rstrip()
auth_tokenf = open('/glade/u/home/rdadata/dssdb/tmp/.globus/globus.auth-token', 'r')
auth_token = auth_tokenf.read().rstrip()

headers = {'Authorization':'Bearer '+transfer_token}

MyGlobus = {
   'url': 'https://transfer.api.globusonline.org/v0.10/',
   'transfer_token': transfer_token,
   'auth_token': auth_token,
   'datashare_ep': 'db57de42-6d04-11e5-ba46-22000b92c6ec',
   'data_request_ep' : 'd20e610e-6d04-11e5-ba46-22000b92c6ec',
   'datashare_ep_base' : '/glade/p/rda/data/',
   'data_request_ep_base' : '/glade/p/rda/transfer/',
   'host_endpoint_id' : 'd33b3614-6d04-11e5-ba46-22000b92c6ec'
}