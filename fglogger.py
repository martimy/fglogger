#!/usr/bin/env python

# Copyright (c) 2017 Maen Artimy
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files 
# (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, 
# publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do 
# so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION 
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


# This script receives syslog messages from a FortiGate device and send them
# to a SQLite database. The script assumes FortiOS 5.4 but it is generic and self-contained. 

import os
import logging
import sqlite3
import socketserver
import pyparsing as pp

sqlite_file = 'fg_log_db.sqlite'    # name of the sqlite database file
HOST, PORT = "0.0.0.0", 514
POLL_INTERVAL = 0.5

class SyslogServer(socketserver.BaseRequestHandler):
	# The syslog server receives messages from the FortiGate on the port
	# defined above. The server sends the log message it to the Database, 
	# which parses it and update the SQlite tables.
	
	db = None
	
	def handle(self):
		data = bytes.decode(self.request[0].strip())
		socket = self.request[1]
		#print( "%s : " % self.client_address[0], str(data))
		SyslogServer.db.update(str(data))
			
	@staticmethod
	def start(mydb):
		SyslogServer.db = mydb
		SyslogServer.db.start()
		try:
			server = socketserver.UDPServer((HOST,PORT), SyslogServer)
			server.serve_forever(poll_interval=POLL_INTERVAL)
		except (IOError, SystemExit):
			raise
		except KeyboardInterrupt:
			print ("Program terminated.")
		finally:
			SyslogServer.db.close()
		
class Database(object):
	# When instantiated, the object searches for a database file in the local directory.
	# If missing, the database is created with one table that includes only the common 
	# header of the Fortigate syslog message.
	
	table_name = "header"
	table_col_name = ["rowid", "date", "time", "devname", "devid", "logid", "type", "subtype", "level", "vd", "msg"] 
	table_col_type = ["INTEGER PRIMARY KEY AUTOINCREMENT", "DATE","TIME","TEXT","TEXT","TEXT","TEXT","TEXT","TEXT","TEXT","TEXT"]

	def __init__(self, fname, parser):
		self.fname = fname
		self.parser = parser

	def start(self):
		if os.path.isfile(self.fname):
			print("Database exists. Connect and wait for updates.")
		else:
			self.create()
			print("Database created!")
		self.connect()
	
	def create(self):
		# Create database file
		self.conn = sqlite3.connect(self.fname)
		c = self.conn.cursor()

		field_list = []
		for n, t in zip(self.table_col_name, self.table_col_type):
			field_list.append(n + " " + t)
		
		statement = "CREATE TABLE " + self.table_name + " (" + ",".join(field_list) +")"
		c.execute(statement)
		
		# Committing changes 
		self.conn.commit()
		self.conn.close()

	def connect(self):
		# connect to the database
		print("connecting the database")
		self.conn = sqlite3.connect(self.fname)
	
	def close(self):
		# close the connection to the database
		print("closing the database")
		self.conn.close()
		
	def update(self, msg):
		# updating the database
		# Parse the log message to extract field names and values
		d = self.parser.parseMsg(msg)
		#print(d)
		c = self.table_col_name
		# column names
		cols = [c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9], c[10]]
		# column values
		values = [d[c[1]], d[c[2]], d[c[3]], d[c[4]], d[c[5]], d[c[6]], d[c[7]], d[c[8]], d[c[9]]]

		dCopy = d.copy()
		for item in cols:
			dCopy.pop(item, None)
		remMsg = str(dCopy).replace("'","")
		#print(msg)

		c = self.conn.cursor()
		statement = "INSERT INTO " + self.table_name \
					+ " (" + ",".join(cols) + ") VALUES" \
					+ " ('" + "','".join(values) + "','" + remMsg +"')" 
		# Surround the values with single quotes 'value1','value2','value3',...
		#print(statement)
		c.execute(statement)
		self.conn.commit()
		
class Parser(object):
	# The syslog message format is a sequence of 'fieldname=fieldvalue'
	# The parser converts the syslog message into a dictionary of [name: value,...]
	
	severity = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Debug"]
		
	def __init__(self):
		priority = pp.Combine(pp.Suppress('<') + pp.Word(pp.nums) + pp.Suppress('>'))
		SEPERATOR = pp.Word("!#$%&'()*+,-./:;<=>?@[\]^_`{|}~")  #all special chars but space and double quotes 
		objName = pp.Combine(pp.Word(pp.alphanums) + pp.ZeroOrMore(SEPERATOR + pp.Word(pp.alphanums)))
		value = (pp.quotedString | objName)
		assgn = pp.Combine(pp.Word(pp.alphas) + "=" + value)
		self.logLine = priority("pri") + pp.OneOrMore(assgn)("fields")

	def parseMsg(self, line):
		dict = {}
		try:
			obj = self.logLine.parseString(line)
			# severity is duplicated by the 'level' field, so it is ignored
			#pri = int(obj.pri) % 8
			#print(severity[pri])
			for field in obj.fields:
				kv = field.split('=')
				#print(kv)
				dict[kv[0]]=kv[1]	
		except pp.ParseException as err:
			print(err.line)
			dict['err']=err.line	
		finally:
			return dict

# Start here			
if __name__ == "__main__":
	# create the syslog message parser
	parser = Parser()
	# create the sqlite3 database
	db = Database(sqlite_file, parser)
	# start the syslog server
	SyslogServer.start(db)
