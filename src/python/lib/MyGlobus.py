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

import os, sys

path1 = "/glade/u/home/gdexdata/lib/python"
path2 = "/glade/u/home/tcram/lib/python"
if (path1 not in sys.path):
	sys.path.append(path1)
if (path2 not in sys.path):
	sys.path.append(path2)

from rda_globus_local_settings import (TRANSFER_REFRESH_TOKEN, AUTH_REFRESH_TOKEN,
                                   CLIENT_ID, CLIENT_SECRET, PRIVATE_KEY,
                                   TRANSFER_RT_QUASAR, AUTH_RT_QUASAR, 
                                   RDA_QUASAR_CLIENT_ID)

#=========================================================================================

GLOBUS_TRANSFER_BASE_URL = 'https://transfer.api.globusonline.org/v0.10/'
GLOBUS_AUTH_BASE_URL = 'https://auth.globus.org/v2/'
GLOBUS_APP_URL = 'https://app.globus.org/'
GLOBUS_SHARE_URL = 'https://app.globus.org/file-manager'
REDIRECT_URI = '/cgi-bin/rdaGlobusTransfer'
RDA_DATA_PATH = '/glade/campaign/collections/gdex'

""" Set up logging directory """
workdir = os.path.join(RDA_DATA_PATH, 'work/tcram')
logdir = os.environ.get('LOGDIR', workdir)
LOGPATH = os.path.join(logdir, 'globus')

""" HTTPS domains """
GLOBUS_DATA_DOMAIN = 'https://data.rda.ucar.edu'
GLOBUS_STRATUS_DOMAIN = 'https://osdata.rda.ucar.edu'
GLOBUS_REQUEST_DOMAIN = 'https://request.rda.ucar.edu'
CGD_HTTPS_DOMAIN = 'https://g-09c647.7a577b.6fbd.data.globus.org'

""" Endpoint IDs """
RDA_DATASET_ENDPOINT = 'b6b5d5e8-eb14-4f6b-8928-c02429d67998'
RDA_DSRQST_ENDPOINT = 'e6cd9f43-935c-42e3-8d19-764d03241719'
NCAR_HOST_ENDPOINT = 'dd1ee92a-6d04-11e5-ba46-22000b92c6ec'

RDA_GLADE_ENDPOINT = '7f0acd80-dfb2-4412-b7b5-ebc970bedf24'
RDA_QUASAR_ENDPOINT = 'e50caa88-feae-11ea-81a2-0e2f230cc907'
RDA_QUASAR_DR_ENDPOINT = '4c42c32c-feaf-11ea-81a2-0e2f230cc907'

RDA_STRATUS_ENDPOINT = 'be4aa6a8-9e35-11eb-8a8e-d70d98a40c8d'
GLOBUS_CGD_ENDPOINT_ID = '11651c26-80c2-4dac-a236-7755530731ac'

GDEX_DATASET_ENDPOINT = 'c4e40965-a024-43d7-bef4-6010f3731b61'
GDEX_DSRQST_ENDPOINT = 'e6cd9f43-935c-42e3-8d19-764d03241719'
GDEX_OS_ENDPOINT = '558ad782-80dd-4656-a64a-2245f38a7c9e' # GDEX Boreas object store endpoint


""" Token storage adapters """
RDA_QUASAR_TOKEN_STORAGE_ADAPTER = "/glade/u/home/gdexdata/lib/python/globus_rda_quasar_tokens.json"

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
    'rda-cgd': GLOBUS_CGD_ENDPOINT_ID,
    'rda#datashare': RDA_DATASET_ENDPOINT,
    'rda#data_request': RDA_DSRQST_ENDPOINT,
    'rda#stratus': RDA_STRATUS_ENDPOINT,
    'rda#cgd': GLOBUS_CGD_ENDPOINT_ID,
	'gdex-data': GDEX_DATASET_ENDPOINT,
    'gdex-request': GDEX_DSRQST_ENDPOINT,
	'gdex-os': GDEX_OS_ENDPOINT,
	'gdex-boreas': GDEX_OS_ENDPOINT
}
