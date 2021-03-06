#!/usr/bin/env python3
#
##################################################################################
#
#     Title : MyGlobus.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 11/10/2016
#   Purpose : Python module defining Globus endpoint IDs, access tokens, and
#             API base URLs.
#
# Work File : $DSSHOME/lib/python/MyGlobus.py*
# Test File : $DSSHOME/lib/python/MyGlobus_test.py*
# Github    : https://github.com/NCAR/rda-globus/python/lib/MyGlobus.py
#
##################################################################################

import sys

path1 = "/glade/u/home/rdadata/lib/python"
path2 = "/glade/u/home/tcram/lib/python"
if (path1 not in sys.path):
	sys.path.append(path1)
if (path2 not in sys.path):
	sys.path.append(path2)

from rda_globus_app_config import (TRANSFER_REFRESH_TOKEN, AUTH_REFRESH_TOKEN,
                                   CLIENT_ID, CLIENT_SECRET, PRIVATE_KEY)

#=========================================================================================

GLOBUS_TRANSFER_BASE_URL = 'https://transfer.api.globusonline.org/v0.10/'
GLOBUS_AUTH_BASE_URL = 'https://auth.globus.org/v2/'
GLOBUS_APP_URL = 'https://app.globus.org/'
REDIRECT_URI = '/cgi-bin/rdaGlobusTransfer'
DSS_DATA_PATH = '/glade/collections/rda'

""" Endpoint IDs """
RDA_DATASET_ENDPOINT = '1e128d3c-852d-11e8-9546-0a6d4e044368'
RDA_DSRQST_ENDPOINT = 'e61f9cde-8537-11e8-9546-0a6d4e044368'
NCAR_HOST_ENDPOINT = 'dd1ee92a-6d04-11e5-ba46-22000b92c6ec'

""" Legacy endpoints no longer used """
RDA_DATASET_ENDPOINT_LEGACY = '2869611a-36aa-11e8-b95e-0ac6873fc732'
RDA_DSRQST_ENDPOINT_LEGACY = '68823254-36aa-11e8-b95e-0ac6873fc732'

""" Older legacy endpoints """
RDA_DATASET_ENDPOINT_LEGACY1 = 'db57de42-6d04-11e5-ba46-22000b92c6ec'
RDA_DATASET_ENDPOINT_LEGACY2 = '2869611a-36aa-11e8-b95e-0ac6873fc732'
RDA_DSRQST_ENDPOINT_LEGACY1 = 'd20e610e-6d04-11e5-ba46-22000b92c6ec'
RDA_DSRQST_ENDPOINT_LEGACY2 = '68823254-36aa-11e8-b95e-0ac6873fc732'

""" Authorization header for vanilla API requests.  No longer used """
# headers = {'Authorization':'Bearer '+TRANSFER_TOKEN}

MyGlobus = {
   'url': GLOBUS_TRANSFER_BASE_URL,
   'transfer_refresh_token': TRANSFER_REFRESH_TOKEN,
   'auth_refresh_token': AUTH_REFRESH_TOKEN,
   'datashare_ep': RDA_DATASET_ENDPOINT,
   'data_request_ep' : RDA_DSRQST_ENDPOINT,
   'datashare_legacy' : 'rda#datashare',
   'data_request_legacy' : 'rda#data_request',
   'datashare_ep_base' : DSS_DATA_PATH + '/data/',
   'data_request_ep_base' : DSS_DATA_PATH + '/transfer/',
   'host_endpoint_id' : NCAR_HOST_ENDPOINT,
   'client_id': CLIENT_ID,
   'client_secret': CLIENT_SECRET,
   'private_key': PRIVATE_KEY,
   'redirect_uri': REDIRECT_URI,
   'globusURL': GLOBUS_APP_URL
}
