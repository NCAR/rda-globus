#!/usr/bin/env python
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

""" 
Include path to Globus SDK if on cheyenne login or compute nodes 
(or load the globus-sdk environment module via the command 'module load globus-sdk'),
or on DAV systems
"""
import sys, socket, re, platform
hostname = socket.gethostname()
if ((hostname.find('cheyenne') != -1) or re.match(r'^r\d{1,2}', hostname)):
	sdk_path_ch = "/glade/u/apps/ch/opt/pythonpkgs/2.7/globus-sdk/1.4.1/gnu/6.3.0/lib/python2.7/site-packages"
	if (sdk_path_ch not in sys.path):
		sys.path.append(sdk_path_ch)
elif ( (hostname.find('geyser') != -1 or hostname.find('caldera') != -1 or hostname.find('pronghorn') != -1 or hostname.find('casper') != -1) ):
	os_dist = platform.linux_distribution()[0]
	if (re.match(r'^CentOS', os_dist)):
		sdk_path_centos = '/glade/u/apps/dav/opt/python/2.7.14/intel/17.0.1/pkg-library/20180510/lib/python2.7/site-packages'
		if (sdk_path_centos not in sys.path):
			sys.path.append(sdk_path_centos)
	else:
		sdk_path_dav = '/glade/u/apps/opt/python/2.7.7/gnu-westmere/4.8.2/lib/python2.7/site-packages'
		if (sdk_path_dav not in sys.path):
			sys.path.append(sdk_path_dav)
else:
	pass

#=========================================================================================

CLIENT_BASE = '/glade/u/home/rdadata/dssdb/tmp/.globus/'
GLOBUS_TRANSFER_BASE_URL = 'https://transfer.api.globusonline.org/v0.10/'
GLOBUS_AUTH_BASE_URL = 'https://auth.globus.org/v2/'
GLOBUS_APP_URL = 'https://www.globus.org/app/'
REDIRECT_URI = '/cgi-bin/rdaGlobusTransfer'
DSS_DATA_PATH = '/glade/collections/rda'

""" Endpoint IDs """
RDA_DATASET_ENDPOINT = '1e128d3c-852d-11e8-9546-0a6d4e044368'
RDA_DSRQST_ENDPOINT = 'e61f9cde-8537-11e8-9546-0a6d4e044368'
NCAR_HOST_ENDPOINT = 'dd1ee92a-6d04-11e5-ba46-22000b92c6ec'

""" Legacy endpoints no longer used """
RDA_DATASET_ENDPOINT_LEGACY1 = 'db57de42-6d04-11e5-ba46-22000b92c6ec'
RDA_DATASET_ENDPOINT_LEGACY2 = '2869611a-36aa-11e8-b95e-0ac6873fc732'
RDA_DSRQST_ENDPOINT_LEGACY1 = 'd20e610e-6d04-11e5-ba46-22000b92c6ec'
RDA_DSRQST_ENDPOINT_LEGACY1 = '68823254-36aa-11e8-b95e-0ac6873fc732'

transfer_refresh_tokenf = open(CLIENT_BASE+'globus.transfer-refresh-token', 'r')
auth_refresh_tokenf = open(CLIENT_BASE+'globus.auth-refresh-token', 'r')
client_idf = open(CLIENT_BASE+'globus.client-id', 'r')
client_secretf = open(CLIENT_BASE+'globus.client-secret', 'r')
private_keyf = open(CLIENT_BASE+'globus.private-key', 'r')

TRANSFER_REFRESH_TOKEN = transfer_refresh_tokenf.read().rstrip()
AUTH_REFRESH_TOKEN = auth_refresh_tokenf.read().rstrip()
CLIENT_ID = client_idf.read().rstrip()
CLIENT_SECRET = client_secretf.read().rstrip()
PRIVATE_KEY = private_keyf.read().rstrip()

transfer_refresh_tokenf.close()
auth_refresh_tokenf.close()
client_idf.close()
client_secretf.close()
private_keyf.close()

headers = {'Authorization':'Bearer '+TRANSFER_TOKEN}

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
