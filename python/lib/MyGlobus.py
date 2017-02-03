#!/usr/bin/env python
#
##################################################################################
#
#     Title : MyGlobus.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 11/10/2016
#   Purpose : Python module defining Globus endpoint IDs and tokens
#
# Work File : $DSSHOME/lib/python/MyGlobus.py*
# Test File : $DSSHOME/lib/python/MyGlobus_test.py*
# Github    : https://github.com/NCAR/rda-globus/python/lib/MyGlobus.py
#
##################################################################################

CLIENT_BASE = '/glade/u/home/rdadata/dssdb/tmp/.globus/'
GLOBUS_TRANSFER_BASE_URL = 'https://transfer.api.globusonline.org/v0.10/'

REDIRECT_URI = '/cgi-bin/rdaGlobusTransfer'

transfer_tokenf = open(CLIENT_BASE+'globus.transfer-token', 'r')
auth_tokenf = open(CLIENT_BASE+'globus.auth-token', 'r')
client_idf = open(CLIENT_BASE+'globus.client-id', 'r')
client_secretf = open(CLIENT_BASE+'globus.client-secret', 'r')
private_keyf = open(CLIENT_BASE+'globus.private-key', 'r')

TRANSFER_TOKEN = transfer_tokenf.read().rstrip()
AUTH_TOKEN = auth_tokenf.read().rstrip()
CLIENT_ID = client_idf.read().rstrip()
CLIENT_SECRET = client_secretf.read().rstrip()
PRIVATE_KEY = private_keyf.read().rstrip()

transfer_tokenf.close()
auth_tokenf.close()
client_idf.close()
client_secretf.close()
private_keyf.close()

headers = {'Authorization':'Bearer '+TRANSFER_TOKEN}

MyGlobus = {
   'url': GLOBUS_TRANSFER_BASE_URL,
   'transfer_token': TRANSFER_TOKEN,
   'auth_token': AUTH_TOKEN,
   'datashare_ep': 'db57de42-6d04-11e5-ba46-22000b92c6ec',
   'data_request_ep' : 'd20e610e-6d04-11e5-ba46-22000b92c6ec',
   'datashare_ep_base' : '/glade/p/rda/data/',
   'data_request_ep_base' : '/glade/p/rda/transfer/',
   'host_endpoint_id' : 'd33b3614-6d04-11e5-ba46-22000b92c6ec',
   'client_id': CLIENT_ID,
   'client_secret': CLIENT_SECRET,
   'private_key': PRIVATE_KEY,
   'redirect_uri': REDIRECT_URI
}