#!/usr/bin/env python
#
##################################################################################
#
#     Title : refresh_globus_tokens.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 04/21/2016
#   Purpose : Refresh the Globus Auth tokens used to authenticate with the Globus
#             APIs.  The Auth tokens are valid for 48 hours, thus this script should
#             be run on a cron job at this frequency.  Instructions including 
#             general syntax to refresh access tokens are provided at 
#             https://developers.google.com/identity/protocols/OAuth2WebServer#offline
#
# Work File   : $DSSHOME/bin/refresh_globus_tokens.py*
# Test File   : $DSSHOME/bin/refresh_globus_tokens_test.py*
# Github repo : https://github.com/NCAR/rda-globus/blob/master/python/refresh_globus_tokens.py
#
##################################################################################

import requests
import subprocess
import os

url = 'https://auth.globus.org/v2/oauth2/token'
idir = '/glade/u/home/tcram/tmp/.globus'
odir = '/glade/u/home/rdadata/dssdb/tmp/.globus'

client_id_file = open(idir+'/globus.client-id', 'r')
client_secret_file = open(idir+'/globus.client-secret', 'r')
transfer_refresh_token_file = open(idir+'/globus.transfer-refresh-token', 'r')
auth_refresh_token_file = open(idir+'/globus.auth-refresh-token', 'r')

client_id = client_id_file.read().rstrip()
client_secret = client_secret_file.read().rstrip()
transfer_refresh_token = transfer_refresh_token_file.read().rstrip()
auth_refresh_token = auth_refresh_token_file.read().rstrip()

client_id_file.close()
client_secret_file.close()
transfer_refresh_token_file.close()
auth_refresh_token_file.close()

transfer_headers = 
{
'client_id':client_id, 
'client_secret': client_secret, 
'refresh_token': transfer_refresh_token,
'grant_type': 'refresh_token'
}

auth_headers = 
{
'client_id':client_id, 
'client_secret': client_secret, 
'refresh_token': auth_refresh_token,
'grant_type': 'refresh_token'
}

# Need to add error checking in API calls
r = requests.post(url, transfer_headers)
data_transfer = r.json()
if (r.status_code >= 400):
	handle_error(r, data_transfer)
else:
	transfer_token = data_transfer['access_token']

r = requests.post(url, auth_headers)
data_auth = r.json()
if (r.status_code >= 400):
	handle_error(r, data_transfer)
else:
	auth_token = data_auth['access_token']

# Write new tokens to output files
transfer_token_file = idir+'/globus.transfer-token-tmp'
transfer_token_output = open(transfer_token_file, 'w')
transfer_token_output.write(transfer_token)
transfer_token_output.close()
os.fchmod(transfer_token_file, 0440)

auth_token_file = idir+'/globus.auth-token-tmp'
auth_token_output = open(auth_token_file, 'w')
auth_token_output.write(auth_token)
auth_token_output.close()
os.fchmod(auth_token_file, 0440)

subprocess.call(['rdacp', '-f', transfer_token_file, '-t', odir+'globus.transfer-token', '-F', '0440'])
subprocess.call(['rdacp', '-f', auth_token_file, '-t', odir+'/globus.auth-token', '-F', '0440'])

#=========================================================================================
def handle_error(r, data):
	msg = "Error {0}: {1}".format(str(r.status_code), data['message'])
	msg += " Resource: {0}".format(data['resource'])
	my_logger.error(msg)
	error_code = r.headers['x-transfer-api-error']
	
	if (error_code == 'EndpointNotFound' or error_code == 'ServiceUnavailable'):
		sys.exit()
	else:
		return
	
