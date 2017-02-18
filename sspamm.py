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

from socket import gethostname

##############################################################################
### Global variables / Configuration
conf = {}

conf["runtime"] = {
	"starttime":	0,
	"endtime":	0,
	"hostname":	None,
	"bindir":	None,
}

##############################################################################
### Configuration

##############################################################################
### Main Functions
def main():
	global conf

	time.sleep(1)
	cleanquit()

def cleanquit():
	global conf

	conf["runtime"]["endtime"] = "%.0f" % time.time()
	print "runtime was %.0f seconds" % (int(conf["runtime"]["endtime"])-int(conf["runtime"]["starttime"]))

	sys.stdout.flush()
	time.sleep(1)
	os._exit(0)

if __name__ == "__main__":
	conf["runtime"]["starttime"] = "%.0f" % time.time()
	conf["runtime"]["startdir"] = os.getcwd()

	os.nice(5)
	locale.setlocale(locale.LC_CTYPE, 'en_US.UTF-8')

	try:
		conf["runtime"]["hostname"] = gethostname()[0:gethostname().index('.')]
	except:
		conf["runtime"]["hostname"] = gethostname()

	conf["runtime"]["bindir"] = sys.argv[0][0:sys.argv[0].rfind("/")]
	if not sys.argv[1:]:
		main()
	else:
		print """We need help here?"""
		sys.exit(1)

sys.exit(0)
