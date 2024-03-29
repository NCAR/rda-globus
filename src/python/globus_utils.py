#!/usr/bin/env python3
#
##################################################################################
#
#     Title : globus_utils.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 02/02/2017
#   Purpose : Python module for Globus Auth and Browse Endpoint utilities
#
# Work File : $DSSHOME/lib/python/globus_utils.py*
# Test File : $DSSHOME/lib/python/globus_utils.py*
# Github    : https://github.com/NCAR/rda-globus/python/globus_utils.py
#
##################################################################################

import globus_sdk
from MyGlobus import MyGlobus

def load_app_client():
	"""Create an AuthClient for the 'NCAR RDA Client' """
	return globus_sdk.ConfidentialAppAuthClient(MyGlobus['client_id'], MyGlobus['client_secret'])

def load_rda_native_client(client_id):
	""" Create an AuthClient for RDA native app clients based on client_id """
	return globus_sdk.NativeAppAuthClient(client_id)