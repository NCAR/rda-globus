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

def add_endpoint_acl_rule(endpoint_id, data):
	""" Create a new endpoint access rule """	
	try:
		rda_identity = "{0}{1}".format(data['email'],'@rda.ucar.edu')
		path = data['path']
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

def construct_share_path(action, data):
	""" Construct the path to the shared data.  Path is relative to the 
	    shared endpoint base path.
	    
	    action = 1: dsrqst share
	           = 2: standard dataset share
	"""
	if (action == 1):
		try:
			cond = " WHERE rindex='{0}' and location IS NOT NULL".format(data['ridx'])
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
				path = "/download.auto/{0}/".format(data['rqstid'])
		except KeyError as err:
			print "Error in construct_share_path: ", err
			sys.exit(1)
	elif (action == 2):
		try:
			path = "/{0}/".format(data['dsid'])
		except KeyError as err:
			print "Error is construct_share_path: ", err
			sys.exit(1)

	return path

def construct_share_url(action, data):
	""" Construct the URL to the shared data on the Globus web app 
	
		action = 1: dsrqst shares
		       = 2: standard dataset share
	"""
	if (action == 1):
		try:
			ridx = data['ridx']
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
			origin_path = construct_share_path(2, {'dsid': data['dsid']})
		except KeyError as err:
			print "Error in construct_share_url", err
			sys.exit(1)

	params = {'origin_id': origin_id, 'origin_path': origin_path}
	if 'identity' in data:
		params.update({'add_identity': data['identity']})
	
	url = '{0}transfer?{1}'.format(MyGlobus['globusURL'], urlencode(params))
	
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

def query_acl_rule(action, data):
	""" Check if an active ACL rule exists for a given RDA user """
	
	if (action == 1):
		""" dsrqst shares """
		try:
			cond = " WHERE rindex='{0}'".format(data['ridx'])
			myrule = myget('dsrqst', '*', cond)
		except KeyError as err:
			print "Error in query_acl_rule: ", err
			sys.exit(1)
		
	elif (action == 2):
		""" standard dataset shares """
		try:
			cond = " WHERE email='{0}' AND dsid='{1}' AND status='ACTIVE'".format(data['email'], data['dsid'])
			myrule = myget('goshare', '*', cond)
		except:
			print "Error in query_acl_rule: ", err
			sys.exit(1)
	
	if 'globus_rid' in myrule:
		rule_id = myrule['globus_rid']
		return {'acl_rule': rule_id}
	else:
		return None
	
	
def update_share_record(action, data):
	""" Update the user's Globus share in RDADB """
	
	try:
		globus_rid = data['globus_rid']
		globus_url = data['globus_url']
	except KeyError as err:
		print "Error in update_share_record: ", err
		sys.exit(1)
	
	record = []
	
	if (action == 1):
		try:
			cond = " WHERE rindex='{0}'".format(data['ridx'])
			record.append({unicode('globus_rid'): data['globus_rid'],
			               unicode('globus_url'): data['globus_url']
			              })
			myupdt('dsrqst', record[0], cond)
		except KeyError as err:
			print "Error in update_share_record: ", err
			sys.exit(1) 
	elif (action == 2):
		try:
			email = data['email']
			cond = " WHERE email='{0}' AND end_date IS NULL".format(data['email'])
			myuser = myget('ruser', ['id'], cond)
			if 'id' not in myuser:
				return {'Error': '[update_share_record] email {0} not in RDADB table ruser'.format(email)}
			record = {'globus_rid': '{0}'.format(data['globus_rid']),
                      'globus_url': '{0}'.format(data['globus_url']),
                      'email': email,
                      'user_id': '{0}'.format(myuser['id']),
                      'username': None,
                      'request_date': date,
                      'source_endpoint': '{0}'.format(data['endpoint']),
                      'dsid': '{0}'.format(data['dsid']),
                      'acl_path': '{0}'.format(data['path']),
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