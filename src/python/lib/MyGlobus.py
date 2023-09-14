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
                                   CLIENT_ID, CLIENT_SECRET, PRIVATE_KEY,
                                   TRANSFER_RT_QUASAR, AUTH_RT_QUASAR, 
                                   RDA_QUASAR_CLIENT_ID)

#=========================================================================================

GLOBUS_TRANSFER_BASE_URL = 'https://transfer.api.globusonline.org/v0.10/'
GLOBUS_AUTH_BASE_URL = 'https://auth.globus.org/v2/'
GLOBUS_APP_URL = 'https://app.globus.org/'
GLOBUS_SHARE_URL = 'https://app.globus.org/file-manager'
REDIRECT_URI = '/cgi-bin/rdaGlobusTransfer'
RDA_DATA_PATH = '/glade/campaign/collections/rda'

""" HTTPS domains """
GLOBUS_DATA_DOMAIN = 'https://data.rda.ucar.edu'
GLOBUS_STRATUS_DOMAIN = 'https://stratus.rda.ucar.edu'
GLOBUS_REQUEST_DOMAIN = 'https://request.rda.ucar.edu'

""" Endpoint IDs """
RDA_DATASET_ENDPOINT = 'b6b5d5e8-eb14-4f6b-8928-c02429d67998'
RDA_DSRQST_ENDPOINT = 'e1e2997e-d794-4868-838e-d4b8d5590853'
NCAR_HOST_ENDPOINT = 'dd1ee92a-6d04-11e5-ba46-22000b92c6ec'

RDA_GLADE_ENDPOINT = 'c3dd5dac-0279-11eb-892e-0a5521ff3f4b'
RDA_QUASAR_ENDPOINT = 'e50caa88-feae-11ea-81a2-0e2f230cc907'
RDA_QUASAR_DR_ENDPOINT = '4c42c32c-feaf-11ea-81a2-0e2f230cc907'

RDA_STRATUS_ENDPOINT = 'be4aa6a8-9e35-11eb-8a8e-d70d98a40c8d'

""" Legacy endpoints no longer used """
RDA_DATASET_ENDPOINT_LEGACY = '2869611a-36aa-11e8-b95e-0ac6873fc732'
RDA_DSRQST_ENDPOINT_LEGACY = '68823254-36aa-11e8-b95e-0ac6873fc732'

""" Older legacy endpoints """
RDA_DATASET_ENDPOINT_LEGACY1 = 'db57de42-6d04-11e5-ba46-22000b92c6ec'
RDA_DATASET_ENDPOINT_LEGACY2 = '2869611a-36aa-11e8-b95e-0ac6873fc732'
RDA_DATASET_ENDPOINT_LEGACY3 = '1e128d3c-852d-11e8-9546-0a6d4e044368'
RDA_DSRQST_ENDPOINT_LEGACY1 = 'd20e610e-6d04-11e5-ba46-22000b92c6ec'
RDA_DSRQST_ENDPOINT_LEGACY2 = '68823254-36aa-11e8-b95e-0ac6873fc732'
RDA_DSRQST_ENDPOINT_LEGACY3 = 'e61f9cde-8537-11e8-9546-0a6d4e044368'

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
   'datashare_stratus' : 'rda#stratus',
   'datashare_ep_base' : RDA_DATA_PATH + '/data/',
   'data_request_ep_base' : RDA_DATA_PATH + '/transfer/',
   'host_endpoint_id' : NCAR_HOST_ENDPOINT,
   'client_id': CLIENT_ID,
   'client_secret': CLIENT_SECRET,
   'private_key': PRIVATE_KEY,
   'redirect_uri': REDIRECT_URI,
   'globusURL': GLOBUS_APP_URL,
   'globus_share_url': GLOBUS_SHARE_URL,
   'rda_quasar_client_id': RDA_QUASAR_CLIENT_ID,
   'transfer_rt_quasar': TRANSFER_RT_QUASAR,
   'auth_rt_quasar': AUTH_RT_QUASAR,
   'rda_glade_endpoint': RDA_GLADE_ENDPOINT,
   'quasar_endpoint': RDA_QUASAR_ENDPOINT,
   'quasar_dr_endpoint': RDA_QUASAR_DR_ENDPOINT,
   'rda_stratus_endpoint': RDA_STRATUS_ENDPOINT
}

# Endpoint dict mapping endpoint display names and aliases to endpoint IDs
MyEndpoints = {
    'NCAR RDA Data Requests': RDA_DSRQST_ENDPOINT,
    'NCAR RDA Dataset Archive': RDA_DATASET_ENDPOINT,
    'NCAR RDA GLADE': RDA_GLADE_ENDPOINT,
    'NCAR RDA Quasar': RDA_QUASAR_ENDPOINT,
    'NCAR RDA Quasar DRDATA': RDA_QUASAR_DR_ENDPOINT,
    'NCAR RDA Stratus': RDA_STRATUS_ENDPOINT,
    'rda-glade': RDA_GLADE_ENDPOINT,
    'rda-quasar': RDA_QUASAR_ENDPOINT,
    'rda-quasar-drdata': RDA_QUASAR_DR_ENDPOINT,
    'rda-stratus': RDA_STRATUS_ENDPOINT,
    'rda#datashare': RDA_DATASET_ENDPOINT,
    'rda#data_request': RDA_DSRQST_ENDPOINT,
    'rda#stratus': RDA_STRATUS_ENDPOINT
}
