#!/usr/bin/env python
#
##################################################################################
#
#     Title : dsglobus.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 02/17/2017
#   Purpose : Python module to create and manage shared endpoints to facilitate
#             Globus data transfers from the RDA.
#
# Work File : $DSSHOME/bin/dsglobus.py*
# Test File : $DSSHOME/bin/dsglobus_test.py*
# Github    : https://github.com/NCAR/rda-globus/python/dsglobus.py
#
##################################################################################

import os, sys

sys.path.append("/glade/u/apps/contrib/modulefiles/globus-sdk")
sys.path.append("/glade/u/home/rdadata/lib/python")
sys.path.append("/glade/u/home/tcram/lib/python")

from MyGlobus import headers, MyGlobus
from PyDBI import myget, myupdt, myadd
import json
from globus_sdk import (TransferClient, TransferAPIError, AccessTokenAuthorizer,
                        AuthClient)
from globus_utils import load_portal_client

try:
    from urllib.parse import urlencode
except:
    from urllib import urlencode
    
def main():
	parse_input()

def add_endpoint_acl_rule(endpoint_id, **kwargs):
	""" Create a new endpoint access rule """	
	try:
		rda_identity = "{0}{1}".format(kwargs['email'],'@rda.ucar.edu')
		path = kwargs['path']
	except KeyError as err:
		print "Error in add_endpoint_acl_rule: ", err
		sys.exit(1)
	
	tc = TransferClient(authorizer=AccessTokenAuthorizer(MyGlobus['transfer_token']))
	identity_id = get_user_id(rda_identity)
	
	rule_data = {
	    "DATA_TYPE": "access",
	    "principal_type": "identity",
	    "principal": identity_id,
	    "path": path,
	    "permissions": "r"
 	}
	result = tc.add_endpoint_acl_rule(endpoint_id, rule_data)
	return {'access_id': result["access_id"]}

def delete_endpoint_acl_rule(id):
	""" Delete a specific endpoint access rule """ 

def construct_share_path(action, **kwargs):
	""" Construct the path to the shared data.  Path is relative to the 
	    shared endpoint base path.
	    
	    action = 1: dsrqst share
	           = 2: standard dataset share
	"""
	if (action == 1):
		try:
			cond = " WHERE rindex='{0}' and location IS NOT NULL".format(kwargs['ridx'])
			rqst_path = myget('dsrqst', ['location'], cond)
			if (len(rqst_path) > 0):
				base_path = MyGlobus['data_request_ep_base']
				loc = rqst_path['location']
				if (loc.find(base_path) != -1):
					path_len = len(base_path)
					path = "/{0}/".format(loc[path_len:])
				else:
					path = None
			else:
				path = "/download.auto/{0}/".format(kwargs['rqstid'])
		except KeyError as err:
			print "Error in construct_share_path: ", err
			sys.exit(1)
	elif (action == 2):
		try:
			path = "/{0}/".format(kwargs['dsid'])
		except KeyError as err:
			print "Error is construct_share_path: ", err
			sys.exit(1)

	return path

def construct_share_url(action, **kwargs):
	""" Construct the URL to the shared data on the Globus web app 
	
		action = 1: dsrqst shares
		       = 2: standard dataset share
	"""
	if 'identity' not in kwargs:
		add_identity = ""
	else:
		add_identity = '&add_identity={0}'.format(kwargs['identity'])
	
	if (action == 1):
		try:
			ridx = kwargs['ridx']
			cond = ' WHERE ridx={0}'.format(ridx)
			myrqst = myget('dsrqst', '*', cond)
			if (len(myrqst) > 0):
				origin_id = MyGlobus['data_request_ep']
				origin_path = "/download.auto/{0}/".format(rqstid)
			else:
				return {'Error': '[construct_share_url] Request {0} not found in RDADB'.format(ridx)}
		except KeyError as err:
			print "Error in construct_share_url", err
			sys.exit(1)

	if (action == 2):
		try:
			origin_id = MyGlobus['datashare_ep']
			origin_path = "/{0}/".format(kwargs['dsid'])
		except KeyError as err:
			print "Error in construct_share_url", err
			sys.exit(1)

	url = '{0}transfer?origin_id={1}&origin_path={2}{3}'.format(MyGlobus['globusURL'], 
	       urlencode(origin_id), urlencode(origin_path), add_identity)
	
	return url
	
def get_user_id(identity):
	""" Get the UUID assigned by Globus Auth. Input argument 'identity' can be one of
	    the following:
	    
	    GlobusID (Globus primary identity): in the form of user@globusid.org
		NCAR RDA identity                 : in the form of user@domain.com@rda.ucar.edu, where user@domain.com is the user's RDA e-mail login
		E-mail identity                   : in the form of user@domain.com
	"""
	ac = AuthClient(authorizer=AccessTokenAuthorizer(MyGlobus['auth_token']))
	result = ac.get_identities(usernames=identity)
	uuid = result.data['identities'][0]['id']
	
	return uuid

def query_acl_rule(action, **kwargs):
	""" Check if an active ACL rule exists for a given RDA user """
	
	if (action == 1):
		""" dsrqst shares """
		try:
			cond = " WHERE rindex='{0}'".format(kwargs['ridx'])
			myrule = myget('dsrqst', '*', cond)
		except KeyError as err:
			print "Error in query_acl_rule: ", err
			sys.exit(1)
		
	elif (action == 2):
		""" standard dataset shares """
		try:
			cond = " WHERE email='{0}' AND dsid='{1}' AND status='ACTIVE'".format(kwargs['email'], kwargs['dsid'])
			myrule = myget('goshare', '*', cond)
		except:
			print "Error in query_acl_rule: ", err
			sys.exit(1)
	
	if 'globus_rid' in myrule:
		rule_id = myrule['globus_rid']
	else:
		rule_id = None
	
	return {'acl_rule': rule_id}
	
def update_share_record(action, **kwargs):
	""" Update the user's Globus share in RDADB """
	
	try:
		globus_rid = kwargs['globus_rid']
		globus_url = kwargs['globus_url']
	except KeyError as err:
		print "Error in update_share_record: ", err
		sys.exit(1)
	
	record = []
	
	if (action == 1):
		try:
			cond = " WHERE rindex='{0}'".format(kwargs['ridx'])
			record.append({unicode('globus_rid'): kwargs['globus_rid'],
			               unicode('globus_url'): kwargs['globus_url']
			              })
			myupdt('dsrqst', record[0], cond)
		except KeyError as err:
			print "Error in update_share_record: ", err
			sys.exit(1) 
	elif (action == 2):
		try:
			email = kwargs['email']
			cond = " WHERE email='{0}' AND end_date IS NULL".format(kwargs['email'])
			myuser = myget('ruser', ['id'], cond)
			if 'id' not in myuser:
				return {'Error': '[update_share_record] email {0} not in RDADB table ruser'.format(email)}
			record = {'globus_rid': '{0}'.format(kwargs['globus_rid']),
                      'globus_url': '{0}'.format(kwargs['globus_url']),
                      'email': email,
                      'user_id': '{0}'.format(myuser['id']),
                      'username': None,
                      'request_date': date,
                      'source_endpoint': '{0}'.format(kwargs['endpoint']),
                      'dsid': '{0}'.format(kwargs['dsid']),
                      'acl_path': '{0}'.format(kwargs['path']),
                      'status': 'ACTIVE'}
			myadd('goshare', record)
		except KeyError as e:
			print "Error in update_share_record: ", err
			sys.exit(1)

	return
	
def parse_input():
	""" Parse command line arguments """

#=========================================================================================
if __name__ == "__main__":
    main()