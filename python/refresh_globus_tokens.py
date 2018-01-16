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

import os, sys
import logging

sys.path.append("/glade/u/home/tcram/lib/python")

from MyGlobus import (CLIENT_BASE, GLOBUS_AUTH_BASE_URL, TRANSFER_TOKEN_FILE, 
                      AUTH_TOKEN_FILE, MyGlobus)

#=========================================================================================
def main():
	# Refresh tokens only if > 46 hours old.
	limit = 46. * 60. * 60.
	check_timestamp(limit)

#=========================================================================================
def check_timestamp(limit):
	""" Check timestamp of token files.  Refresh if > 46 hours old.  Input parameter 
	    limit is provided in units of seconds.
	"""

	import time

	now = time.time()
	msg = "Current epoch: {}".format(now)
	my_logger.info("[check_timestamp] {}".format(msg))

	# check timestamp of token files.  Refresh if > 47 hours old.
	auth_mod_epoch = os.path.getmtime(CLIENT_BASE+AUTH_TOKEN_FILE)
	transfer_mod_epoch = os.path.getmtime(CLIENT_BASE+TRANSFER_TOKEN_FILE)
	auth_mod_time = time.ctime(auth_mod_epoch)
	transfer_mod_time = time.ctime(transfer_mod_epoch)

	msg = "Auth file last modified (epoch): {}".format(auth_epoch)
	my_logger.info("[check_timestamp] {}".format(msg))
	msg = "Transfer file last modified (epoch): {}".format(transfer_epoch)
	my_logger.info("[check_timestamp] {}".format(msg))
	msg = "Auth token file last modified: {}".format(auth_mod_time) 
	my_logger.info("[check_timestamp] {}".format(msg))
	msg = "Transfer token file last modified: {}".format(transfer_mod_time) 
	my_logger.info("[check_timestamp] {}".format(msg))

	delta_auth = now - auth_mod_epoch
	delta_transfer = now - transfer_mod_epoch

	msg = "Auth timestamp offset (seconds): {}".format(delta_auth)
	my_logger.info("[check_timestamp] {}".format(msg))
	msg =  "Transfer timestamp offset (seconds): {}".format(delta_transfer)
	my_logger.info("[check_timestamp] {}".format(msg))

	if (max(delta_auth, delta_transfer) > limit):
		print "Refreshing tokens"
		# refresh_tokens()
	else:
		msg = "Tokens are up to date.  Refresh not required."
		print msg
		my_logger.info("[check_timestamp] {}".format(msg))
	return
	
#=========================================================================================
def refresh_tokens():
	import requests, subprocess, stat

	url = GLOBUS_AUTH_BASE_URL + 'oauth2/token'
	tmpdir = '/glade/u/home/tcram/tmp/.globus'
	transfer_token_file_tmp = tmpdir + '/' + 'globus.transfer-token-tmp'
	auth_token_file_tmp = tmpdir + '/' + 'globus.auth-token-tmp'

	client_id = MyGlobus['client_id']
	client_secret = MyGlobus['client_secret']
	transfer_refresh_token = MyGlobus['transfer_refresh_token']
	auth_refresh_token = MyGlobus['auth_refresh_token']
	
	transfer_headers = {'client_id': client_id, \
                    'client_secret': client_secret, \
                    'refresh_token': transfer_refresh_token, \
                    'grant_type': 'refresh_token'}

	auth_headers = {'client_id': client_id, \
                'client_secret': client_secret, \
                'refresh_token': auth_refresh_token, \
                'grant_type': 'refresh_token'}

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
	transfer_token_output = open(transfer_token_file_tmp, 'w')
	transfer_token_output.write(transfer_token)
	transfer_token_output.close()

	auth_token_output = open(auth_token_file_tmp, 'w')
	auth_token_output.write(auth_token)
	auth_token_output.close()

	transfer_token_fd = os.open(transfer_token_file_tmp, os.O_RDONLY)
	auth_token_fd = os.open(auth_token_file_tmp, os.O_RDONLY)
	os.fchmod(transfer_token_fd, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
	os.fchmod(auth_token_fd, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
	os.close(transfer_token_fd)
	os.close(auth_token_fd)

	subprocess.call(['rdacp', '-f', transfer_token_file_tmp, '-t', CLIENT_BASE+TRANSFER_TOKEN_FILE, '-F', '0440'])
	subprocess.call(['rdacp', '-f', auth_token_file_tmp, '-t', CLIENT_BASE+AUTH_TOKEN_FILE, '-F', '0440'])

	# os.remove(transfer_token_file_tmp)
	# os.remove(auth_token_file_tmp)
	
	msg = "Transfer and auth tokens have been successfully updated."
	print msg
	my_logger.info(msg)

	return

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

#=========================================================================================
# Configure log file

def configure_log(**kwargs):
	""" Set up log file """
	LOGPATH = '/glade/scratch/tcram/logs'
	LOGFILE = 'refresh_globus_tokens.log'

	if 'level' in kwargs:
		loglevel = kwargs['level']
	else:
		loglevel = 'info'

	LEVELS = { 'debug':logging.DEBUG,
               'info':logging.INFO,
               'warning':logging.WARNING,
               'error':logging.ERROR,
               'critical':logging.CRITICAL,
             }

	level = LEVELS.get(loglevel, logging.INFO)
	my_logger.setLevel(level)
	handler = logging.handlers.RotatingFileHandler(LOGPATH+'/'+LOGFILE,maxBytes=200000000,backupCount=10)
	handler.setLevel(level)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	my_logger.addHandler(handler)
	
	return

#=========================================================================================
""" Set up logging """
my_logger = logging.getLogger(__name__)
configure_log(level='info')

if __name__ == "__main__":
	main()

