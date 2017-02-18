#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""Semi's SPAM Milter
"""
__author__ = "Sami-Pekka Hallikas <semi@hallikas.com>"
__email__ = "semi@hallikas.com"
__date__ = "19 Feb 2017"
__version__ = "4.0-devel"

import sys
import os
import locale
import time
import re

from socket import gethostname

##############################################################################
### Global variables / Configuration
conf = {}

conf["runtime"] = {
	"hostname":	None,
	"bindir":	None,
	"startdir":	None,
	"starttime":	0,
}

##############################################################################
### Configuration

##############################################################################
### Variable tools (we save/load variables)
def show_vars(var, lvl=0):
	if lvl==0: lvl=1
	st=""
	tab = "\t"

	if type(var) is dict:
		st += "{\n"
		for k in var.keys():
			st += tab*lvl
			if(0): # Reserve space for keys
				if type(k) is int:
					st += "%-16s" % ("%d: " % k)
				else:
					st += "%-16s" % ("\"%s\": " % k)
			else:
				if type(k) is int:
					st += "%d: " % k
				else:
					st += "\"%s\": " % k
			st += show_vars(var[k], lvl+1)
			st += ",\n"
		st += tab*(lvl-1)
		st += "}"
	elif type(var) is tuple:
		if len(var) < 1:
			st += str(var)
		else:
			st += "(\n"
			for k in var:
				st += tab*lvl
				st += show_vars(k, lvl+1)
				st += ",\n"
			st += tab*(lvl-1)
			st += ")"
	elif type(var) is list:
		if len(var) < 1:
			st += str(var)
		elif len(var) == 1 and type(var[0]) in [str, int]:
			st += str(var)
		else:
			st += "[\n"
			for k in var:
				st += tab*lvl
				st += show_vars(k, lvl+1)
				st += ",\n"
			st += tab*(lvl-1)
			st += "]"
	elif type(var) is str:
		st += "\'%s\'" % re.sub("\'", "\\\'", var)
	elif type(var) is int:
		st += "%d" % var
	elif var == None:
		st += "None"
	else:
		st += str(var)
	return st


##############################################################################
### Main Functions
def main():
	global conf

	time.sleep(1)
	print show_vars(conf)
	cleanquit()

def cleanquit():
	global conf

	endtime = "%.0f" % time.time()
	print "runtime was %.0f seconds" % (int(endtime)-int(conf["runtime"]["starttime"]))

	sys.stdout.flush()
	time.sleep(1)
	os._exit(0)

if __name__ == "__main__":
	try:
		conf["runtime"]["hostname"] = gethostname()[0:gethostname().index('.')]
	except:
		conf["runtime"]["hostname"] = gethostname()

	conf["runtime"]["startdir"] = os.getcwd()
	conf["runtime"]["bindir"] = sys.argv[0][0:sys.argv[0].rfind("/")]
	if not os.path.exists(conf["runtime"]["bindir"]):
		conf["runtime"]["bindir"] = os.getcwd()
	conf["runtime"]["starttime"] = "%.0f" % time.time()

	locale.setlocale(locale.LC_CTYPE, 'en_US.UTF-8')

	os.nice(5)
	if not sys.argv[1:]:
		main()
	else:
		print """We need help here?"""
		sys.exit(1)

sys.exit(0)
