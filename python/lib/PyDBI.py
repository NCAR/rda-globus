#!/usr/bin/env python
#
##################################################################################
#
#     Title : PyDBI.py
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 02/06/2015
#   Purpose : Python module for MySQL database functions
#
# Work File : $HOME/lib/python/PyDBI.py*
# Test File : $HOME/lib/python/PyDBI_test.py*
#  SVN File : $HeadURL: https://subversion.ucar.edu/svndss/tcram/python/PyDBI.py $
#
##################################################################################

import os, sys
import mysql.connector
from mysql.connector import errorcode

dbconfig = {'user': os.environ['DBUSER'], \
            'password': os.environ['DBPWD'], \
            'database': os.environ['DBUSER'], \
            'host': os.environ['DBHOST'], \
            'port': 3306}

#=========================================================================================
# Function dbconnect: Create database connection

def dbconnect():
	try:
		db = mysql.connector.connect(**dbconfig)
		return db
	except mysql.connector.Error as err:
		if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
			print "Incorrect database user name/password combination"
			sys.exit(1)
		elif err.errno == errorcode.ER_BAD_DB_ERROR:
			print "Database %s does not exist" % dbconfig['database']
			sys.exit(1)
		else:
			print "Error: ", err
			sys.exit(1)

#=========================================================================================
# Function pyclose: Close database connection

def dbclose(db):
	try:
		db.close()
	except mysql.connector.Error as err:
		print "Error %d" % err.errno
		sys.exit(1)

#=========================================================================================
# Function myget: retrieve one record from tablename
#
# tablename: DB table name
# fields   : comma-delimited list of one or more field names
# condition: query condition for WHERE clause
#
# Returns: a dictionary of key/value pairs from the query result 
#          set (dict is empty if no results)

def myget(tablename, fields, condition):
	try:
		db = dbconnect()
		c = db.cursor()
		fields = ",".join(fields)
		sqlstr = "SELECT %s FROM %s" % (fields, tablename)
		try:
			sqlstr += " " + condition
		except NameError:
			pass
		c.execute(sqlstr)
		cols = c.column_names
		rows = c.fetchall()
		dbclose(db)
		if len(rows) > 0:
			return dict(zip(cols,rows[0]))
		else:
			return {}
	except mysql.connector.Error as err:
		print "Error: ", err
		sys.exit(1)

#=========================================================================================
# Function mymget: retrieve one or more records from tablename
#
# tablename: DB table name
# fields   : comma-delimited list of one or more field names
# condition: query condition for WHERE clause
#
# Returns: a list of dictionaries containing key/value pairs from the query result 
#          set (dict is empty if no results)

def mymget(tablename, fields, condition):
	allrows = []
	try:
		db = dbconnect()
		c = db.cursor()
		fields = ",".join(fields)
		sqlstr = "SELECT %s FROM %s" % (fields, tablename)
		try:
			sqlstr += " " + condition
		except NameError:
			pass
		c.execute(sqlstr)
		cols = c.column_names
		rows = c.fetchall()
		nrows = c.rowcount
		dbclose(db)
		if nrows > 0:
			for i in range(nrows):
				allrows.append(dict(zip(cols,rows[i])))
			return allrows
		else:
			return {}
	except mysql.connector.Error as err:
		print "Error: ", err
		sys.exit(1)

#=========================================================================================
# Function myadd: insert one record into tablename
#
#          tablename: add one record for one table name for each call
#             record: dictionary with keys as field names and
#                     values as field values
#
def myadd(tablename, record):
	try:
		db = dbconnect()
		c = db.cursor()
		fields = []
		values = []
		for key in record:
			fields.append(str(key).encode('utf8'))
		fields = "(" + ",".join(fields) + ")"
		for val in record.values():
			if val == None:
				values.append(val)
			else:
				values.append(str(val))
		values = tuple(values)
		valpl = ['%s'] * len(values)
		valpl = "(" + ",".join(valpl) + ")"
		sqlstr = "INSERT INTO %s %s VALUES %s" % (tablename, fields, valpl)
		c.execute(sqlstr, values)
		db.commit()
		dbclose(db)
		print "One record added to table %s" % tablename
	except mysql.connector.Error as err:
		print "table: "+tablename
		print record
		print "Error in myadd: ", err
		sys.exit(1)
		
#=========================================================================================
# Function mymadd: insert multiple records into tablename
#
# uses the method cursor.executemany()

#def mymadd(tablename, records):
		
		
#=========================================================================================
# Function myupdt: update one record in tablename
#
#          tablename: add one record for one table name for each call
#             record: dictionary with keys as field names and
#                     values as field values
#
def myupdt(tablename, record, condition, print=None):
	try:
		db = dbconnect()
		c = db.cursor()
		fields = []
		values = []
		for key in record:
			field = str(key).encode('utf8')
			setstr = "{0}=%s".format(field)
			fields.append(setstr)
		fields = ",".join(fields)
		sqlstr = "UPDATE %s SET %s" % (tablename, fields)
		try:
			sqlstr += " " + condition
		except NameError:
			pass
		for val in record.values():
			if (val == None):
				values.append(val)
			else:
				values.append(str(val))
		values = tuple(values)
		c.execute(sqlstr, values)
		db.commit()
		dbclose(db)
		if print:
			print "One record updated in table %s" % tablename
	except mysql.connector.Error as err:
		print record
		print condition
		print "Error in myupdt: ", err
		sys.exit(1)

#=========================================================================================
#def mydel():

#=========================================================================================
# Function prepare_insert: Prepare a SQL insert statement for pyadd()
#def prepare_insert(tablename, record):
