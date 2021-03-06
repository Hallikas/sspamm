#!/usr/bin/env python
# -*- coding: ISO-8859-15 -*-

# Note, I will use d.m.yyyy format, that's 19 feb 2017 = 19.2.2017

"""Semi's SPAM Milter
"""
__program__ = "Semi's Spam Milter"
__prog__ = "sspamm"
__author__ = "Sami-Pekka Hallikas <semi@hallikas.com>"
__email__ = "semi@hallikas.com"
__date__ = "19 Feb 2017"
__version__ = "4.0-devel"

import argparse
import sys
import os
import locale
import time
import re
import thread
import ConfigParser

from socket import gethostname

from signal import signal, SIGINT, SIGHUP, SIGBUS, SIGTERM
from traceback import print_exc

from email import message_from_file, message_from_string
from email.Header import decode_header

from string import maketrans, letters, digits, punctuation, whitespace
from string import split, join

import formatter, htmllib

UseSHA=0
try:
# For python > 2.4
	UseSHA=25
	import hashlib

except:
# For Python >= 2.4
	UseSHA=24
	import sha

## LOG_EMERG		= 0		# system is unusable
## LOG_ALERT		= 1		# action must be taken immediately
## LOG_CRIT		= 2		# critical conditions
## LOG_ERR		= 3		# error conditions
## LOG_WARNING		= 4		# warning conditions
## LOG_NOTICE		= 5		# normal but significant condition
## LOG_INFO		= 6		# informational
## LOG_DEBUG		= 7		# debug-level messages
from syslog import \
	LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, \
	LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG

## http://sourceforge.net/projects/pymilter
## Ubuntu: spf-milter-python or "apt-get -y install python-milter"
##
import Milter
from milter import \
	ACCEPT, CONTINUE, REJECT, DISCARD, TEMPFAIL, \
	ADDHDRS, CHGBODY, ADDRCPT, DELRCPT, CHGHDRS

try: from milter import QUARANTINE
except: pass

## http://sourceforge.net/projects/pydns
## Ubuntu: "apt-get -y install python-dns"
try:
	import DNS
	from DNS import Base
	usedns = True
	DNS.defaults['server'].append('8.8.8.8')
	DNS.defaults['timeout'] = 5
except:
	usedns = False


##############################################################################
### Global variables / Configuration
conffile = "sspamm.conf"

# Data types of configuration options
opt_int = { "main/verbose", "main/offline", "main/crchours", "settings/maxbodysize" }

# Default values of configuration file
confdefaults = {
	"main": {
		"name":			"sspamm4",
		"sspammdir":		None,
		"pid":			"sspamm4.pid",
		"childs":		False,
		"port":			"local:/tmp/sspamm4.sock",
		"logfile":		"sspamm4.log",
		"rrdfile":		"sspamm4.rrd",
		"crcfile":		"sspamm4.crc",
		"verbose":		1,
		"offline":		3,
		"timeme":		True,
		"tmpdir":		"/dev/shm",
		"savedir":		None,
		"nonspamonly":		False,
		"confbackup":		True,
		"crcsave":		False,
		"crchours":		12,
		"watchmode":		False,
	},
	"filter": {
		"defaulttests":		["connect", "helo"],
		"domains":		[],
		"rules":		[],
	},
	"actions": {
		"connect":		"Flag",
		"helo":			"Flag",
		"samefromto":		"Flag",
		"ipfromtopre":		"Flag",
		"ipfromto":		"Flag",
		"headers":		"Flag",
		"dyndns":		"Flag",
		"wordscan":		"Flag",
		"bayesian":		"Flag",
		"rbl":			"Flag",
		"charset":		"Flag",
		"crc":			"Flag",
	},
	"settings": {
		"ipservers":		["dnsbl-2.uceprotect.net"],
		"maxbodysize":		1024,
	},
	"rules": {
		"hide":			[],
		"connect":		["(?#ignore)(127.0.0.1)"],
		"helo":			[],
		"ipfromtopre":		[],
		"ipfromto":		[],
		"headers":		[],
		"charset":		[],
		"dyndns":		[
					"^[0-9]{1,3}[\-\.][0-9]{1,3}[\-\.][0-9]{1,3}[\-\.][0-9]{1-3}\..*",
		],
		"subject":		[],
		"links":		[],
		"blockwords":		[],
		"blockhtml":		[],
	},
}
conf = confdefaults.copy()

conf["runtime"] = {
	"hostname":	None,
	"bindir":	None,
	"startdir":	None,
	"starttime":	0,
	"conffile":	None,
	"conftime":	0,
	"offline":	False,
	"nodebug":	False,
	"rrd":		{
		"ham":		0,
		"unsure":	0,
		"spam":		0,
	},
}

# For CRC
msgtemplate = {
	'firstseen': 0,
	'lastseen': 0,
	'seen': 0,
	'block': 0,
	'pass': 0,
	'flag': 0,
}

# Data types of options:
opt_int = { "main/verbose", "main/offline", "main/crchours", "settings/maxbodysize" }
opt_bool= { "main/childs" }
opt_list= { "filter/defaulttests", "settings/ipservers", }

##############################################################################
### Tools to parse configuration
class MyParser(ConfigParser.ConfigParser):
# Checked 22.2.2017, - Semi
	def getlist(self,section,option,default=None,warn=False):
		try:
			value = self.get(section, option)
			(value, count) = re.compile(",|;|\n").subn(' ', value)
			t = value.split()
			try:
				if t[0] == "": t.remove('')
			except IndexError:
				t = []
			return t
		except ConfigParser.NoOptionError, (err):
			if warn: debug(err, LOG_ERR)
			pass
		except:
			err = "Warning: No list for %s: %s" % (section, option)
			if warn: debug(err, LOG_ERR)
			return None
		return default

# Checked 22.2.2017, - Semi
	def getlines(self,section,option,default=None,warn=False):
		try:
			value = self.get(section, option)
			t = value.split('\n')
			try:
				if t[0] == "": t.remove('')
			except IndexError:
				t = []
			return t
		except ConfigParser.NoOptionError, (err):
			if warn: debug(err, LOG_ERR)
			pass
		except:
			err = "Warning: No lines for %s: %s" % (section, option)
			if warn: debug(err, LOG_ERR)
			return None
		return default

# Checked 22.2.2017, - Semi
	def getdomains(self,section,option,default=None,warn=False):
		t = []
		tmp = []
		for i in self.getlines(section,option,[]):
			i=re.sub("[\t ]", "", i).split(":")
			if len(i) == 1: i.append("all")

			key=i[0].split(",")
			del i[0]
			tests=i[0].split(",")
			if '' in tests: tests.remove('')
			t.append([key, tests])

		for val in t:
### On filter/domains. If no rules are defined, add all. Also append rules if
### defined with + on domain(s). And remove from default rules if prefixed
### with ! or -.

			rules = 0
			for test in val[1]:
				if test[0] >= 'a' and test[0] <= 'z': rules += 1
			if rules == 0 or not val[1]: val[1].append('all')

			tests = []
			seen = []
			for test in val[1]:
				if test[0] in ["-", "!"]:
					seen.append(test[1:])
				elif test[0] == "+":
					tests.append(test[1:])
				elif test == "all":
					tests += conf["filter"]["defaulttests"]
				else: tests.append(test)

			val[1] = []
			for test in tests:
				if test in seen: continue
				val[1].append(test)

			for k in val[0]:
				tmp.append((k, val[1]))
		return tmp

# Checked 22.2.2017, - Semi
	def getrules(self,section,option,default=None,warn=False):
		t = []
		tmp = []
		n=0
		for i in self.getlines(section,option,[]):
			n=n+1
			i=re.sub("\t| ", "", i).split(":")
			if '' in i: i.remove('')
			if len(i) > 1:
				t.append((i[0].split(","), ",".join(i[1:]).split(",")))
		for val in t:
			for k in val[0]:
				tmp.append((k, val[1]))
		return tmp

##############################################################################
### Configuration
def maildef():
	return {
		"id": 0,
		"tmpfile": None,
		"from": [],
		"to": [],
		"header": {},
		"received": {
			1: {
				"ip": None,
				"dns": None,
				"helo": None,
			}
		},
		"subject": {},
		"raw": '',
		"timer": {},
		"result": {},
	}


# Checked 22.2.2017, - Semi
def load_config(file):
	global conf

	debug("load_config(\"%s\")" % (file), LOG_DEBUG)
	tmpconf = conf.copy()

	if not os.access(file, os.R_OK):
		debug("FATAL: Can't access %s." % (file), LOG_CRIT)
		return False

# cp = config parser object
	try:
		cp = MyParser()
		cp.read(file)
	except:
		debug("CONFIG LOAD ERROR. %s: %s" % (sys.exc_type, sys.exc_value), LOG_CRIT)
		print_exc(limit=None, file=sys.stderr)
		return False

	if not (cp.has_section("main")):
		debug("FATAL: Main section is missing!", LOG_CRIT)
		return False

	try:
		conf["main"]["verbose"] = cp.getvalue("main", "verbose")
	except:
		pass

	conf["main"]["sspammdir"] = cp.get("main", "sspammdir")
	if conf["main"]["sspammdir"] and conf["main"]["sspammdir"][0] not in ["/", "."]:
		conf["main"]["sspammdir"] = "%s/%s" % (conf["runtime"]["confpath"], conf["main"]["sspammdir"])

### Everything is ready, we have config file readed into cp object. Now we need to process it.
	for s in cp.sections():
		if not conf.has_key(s): conf[s] = {}
		for o in cp.options(s):
			if not conf[s].has_key(o): conf[s][o] = None

# Read option into global conf
			if 0: # This is just stupid, I know. But I do it so I can use elif on every other section
				pass
			elif "%s/%s" % (s,o) in opt_int:
				conf[s][o] = cp.getint(s,o)
			elif "%s/%s" % (s,o) in opt_list:
				conf[s][o] = cp.getlist(s,o)
### Filter/domains and filter/rules are very special cases and needs some special parsing
			elif "%s/%s" % (s,o) in ["filter/domains"]:
				conf[s][o] = cp.getdomains(s,o)
			elif "%s/%s" % (s,o) in ["filter/rules"]:
				conf[s][o] = cp.getrules(s,o)
			elif s == "main":
# Strings in main section could have 'smart tags' like %h = hostname, etc.
# Pass thru config_variables() for rewrite
				conf[s][o] = config_variables(cp.get(s,o))
# If variable is filename or path, does it need sspammdir prefix?
				if o in ["pid", "logfile", "savedir", "tmpdir", "crcfile", "rrdfile"]:
					conf[s][o] = cp.get(s,o)
					if conf[s][o].rfind("%") > -1:
						conf[s][o] = config_variables(conf[s][o])
					elif conf[s][o][0] not in ["/", "."]:
						conf[s][o] = config_variables("%s/%s" % (conf["main"]["sspammdir"], conf[s][o]))
				else:
					conf[s][o] = config_variables(cp.get(s,o))
			else:
				conf[s][o] = cp.get(s,o)

# Config entry is now readed into global variable conf (single line is conf[s][o])
# Fix datatypes, like None and boolean
			if conf[s][o] == "None":
				conf[s][o] = None
			elif "%s/%s" % (s,o) in opt_bool:
				if conf[s][o] in ["Yes", "True", "1"]:
					conf[s][o] = True
				else:
					conf[s][o] = False
			elif "%s/%s" % (s,o) in opt_int:
				try:
					conf[s][o] = int(conf[s][o])
				except:
					debug("Bad type of option %s/%s, should be integer" % (s,o), LOG_ERR)
			elif s in [ "actions" ]:
				conf[s][o] = conf[s][o].lower()

# We need to find and rewrite 'our special regexp' (_ip and _dns) to real regexp.
# Notice, even SPACE is rule separator!
			if s in ["rules"]:
				if 0:
					pass
				elif o in ["ipfromtopre", "ipfromto"]:
					pass
				elif o in ["subject", "blockwords", "blockhtml"]:
					pass
				elif o in ["hide"]:
					pass
				elif o in ["connect"]:
					pass
				elif o in ["helo"]:
					pass
				elif o in ["dyndns"]:
					pass
				elif o in ["charset"]:
					pass
				elif o in ["headers"]:
					pass
				elif o in ["links"]:
					pass
				else:
#					print "\n%s/%s:" % (s,o),
#					print show_vars(conf[s][o])
					pass
# We have no try/exception for now, we SHOULD do it. But I need to have more samples how to crash this.
#	except ConfigParser.NoOptionError, (err):
#		debug("%s" % err, LOG_ERR)
#		print_exc(limit=None, file=sys.stderr)
	return

# Checked 22.2.2017, - Semi
def save_config(file):
	global conf

	try:
		fp = open("%s.dump" % (file), "w+b")
		tmpconf = conf.copy()
		del tmpconf["runtime"]
		fp.write(show_vars(tmpconf))
		fp.close()
	except:
		pass
	return

# Checked 22.2.2017, - Semi
def config_variables(t):
	global conf
# Translate %n, %h, %s and %c variables at main section of configuration file
	t = re.sub("%n", conf["main"]["name"], t)
	t = re.sub("%h", conf["runtime"]["hostname"], t)
	if conf["main"].has_key("sspammdir") and conf["main"]["sspammdir"]:
		t = re.sub("^.*%s", conf["main"]["sspammdir"], t)
	if conf["runtime"].has_key("confpath") and conf["runtime"]["confpath"]:
		t = re.sub("^.*%c", conf["runtime"]["confpath"], t)
	return t


##############################################################################
### Variable tools (we save/load variables)
# Checked 19.2.2017, - Semi
def save_vars(var, fname, id=None):
	debug("save_vars(\"%s\")" % (fname), LOG_DEBUG, id=id)
	fp = open(fname, "w+b")
	if fp: fp.write(show_vars(var))
	if fp: fp.write("\n")
	fp.close()
	return

# Note: This should be confirmed by someone else
# Checked 19.2.2017, - Semi - NOTE!
def load_mailvar(fname, id=None):
	debug("load_mailvar(\"%s\")" % (fname), LOG_DEBUG, id=id)
	do_skip = False
	is_raw = False
	wasrec = False

	name = None
	hname = None

	var_work = ""
	var_rec = ""
	var_raw = ""
	var_hraw = ""
# We really should have better parser here! I know, this is quite lame
	with open(fname, "r") as fp:
		i=0
		for line in fp:
			n = len(line)
			if n > 80: n=80

			if is_raw:
				if line[0:-1] == "',":
					is_raw = False
				elif line[-3:-1] == "',":
					if line[-4] is not "\\":
						is_raw = False
			else:
				res = is_listed("^\W\"(?P<name>[\w-]+)\":", line)
				if res and res[0]:
					name=res[4]["name"]
					do_skip = False
					if name == "raw": is_raw = True
					if name == "header": continue

				res = is_listed("^\W[\)\]}],|^\}", line)
				if res and res[0]:
					if wasrec:
						var_rec += line
						wasrec=False
					do_skip = False
					if name in ["id", "from", "to", "my"]:
						var_work += line
						name = None
						continue
					name = None

			if name in ["received"]:
				var_rec += line
				wasrec=True
				continue

			if name in ["header"]:
				res = is_listed("^\W+\"(?P<name>[\w-]+)\":", line)
				if res and res[0]:
					hname = res[4]["name"]
					if hname == "raw":
						is_raw = True
						var_hraw = line
				elif hname in ["raw"]:
					var_hraw += line

			if name in ["id", "from", "to", "my"]:
				var_work += line
			if name in ["raw"]:
				var_raw += line

	fp.close()
	vars = eval("{\n%s\n}" % (var_work))
	var_tmp = eval("{\n%s\n}" % (var_rec))

	vars["received"] = {}
	vars["received"][1] = var_tmp["received"][1]
	if var_hraw:
		vars["header"] = {}
		vars["header"]["raw"] = var_hraw[10:-3]
	vars["raw"] = var_raw[9:-3]

	return vars

# Note: This should be confirmed by someone else
# Checked 19.2.2017, - Semi
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

#
def load_vars(fname, id=None):
	debug("load_vars(\"%s\")" % (fname), LOG_DEBUG, id=id)
	fp = open(fname, "r")
	is_raw = False
	raw = None
	do_skip = False
	buf = ""
	while 1:
		line = fp.readline()
		if len(line) < 1: break
		if line[1:10] == "\"mime\": {":
			do_skip = True
		if line[1:13] == "\"raw\": 'From":
			raw = line[9:]
			is_raw = True
		elif is_raw:
			if line == "',\n":
				is_raw = False
			else:
				raw += line
		elif do_skip:
			if line[1:3] == "},":
				do_skip = False
			pass
		else:
			buf += line
	fp.close()
	vars = eval(buf)
	if raw: vars["raw"] = raw
	return vars

##############################################################################
### Custom tools
class HTMLStripper(htmllib.HTMLParser):
	def __init__(self):
#		debug("HTMLStripper.__init__()", LOG_DEBUG)
		self.bodytext = StringIO.StringIO()
		writer = formatter.DumbWriter(self.bodytext)
		htmllib.HTMLParser.__init__(self, formatter.AbstractFormatter(writer))

	def anchor_end(self):
#		debug("HTMLStripper.anchor_end()", LOG_DEBUG)
		if self.anchor:
			self.handle_data('')
			self.anchor = None

	def gettext(self):
#		debug("HTMLStripper.gettext()", LOG_DEBUG)
		return self.bodytext.getvalue()

## Used for trace processing time, so we can find if there is things that takes too long to complete
def timeme(timer=0):
	if timer == 0: return time.time()
	timer = float(time.time())-float(timer)
	if timer < 0: timer = 0
	return float(timer)

## Get only address part of address string. Do lowercase and strip blanks.
## Also return all parsed addresses as array.
def parse_addrs(addr, id=None):
	debug("parse_addrs(\"%s\")" % (addr), LOG_DEBUG, id=id)
	addr=re.sub(" ", "", re.sub(' ?[("].*?[)"]', "", addr.lower().strip()))
	if addr.startswith("<") or addr.endswith(">"):
		return [addr[addr.find("<")+1:addr.rfind(">")]]
	elif addr.find(","):
		return addr.split(",")
	else:
		return [addr]

### Test if IP or HOSTNAME is local
def islocal(a, id=None):
	debug("islocal(\"%s\")" % (a), LOG_DEBUG+1, id=id)
	try:
		b = re.search("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", a)
		if b:
			# Is IP
			if re.search("^127\.", a): return True
		else:
			# is Name
			if a in ["localhost"]: return True
	except:
		debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)

	return False

### Test if IP or HOSTNAME is local/private
def isprivate(a, id=None):
	debug("isprivate(\"%s\")" % (a), LOG_DEBUG+1, id=id)
	try:
		if islocal(a, id): return True
	except:
		pass
	try:
		b = re.search("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", a)
		if b:
			# Is IP
			# List collected from https://en.wikipedia.org/wiki/Reserved_IP_addresses
			if re.search("^10\.", a): return True
			if re.search("^100\.(6[4-9]|([7-9]|1[01])[0-9]|12[0-7])\.", a): return True
			if re.search("^169\.254\.", a): return True
			if re.search("^172\.(1[6-9]|2[0-9]|3[01])\.", a): return True
			if re.search("^192\.0\.0\.", a): return True
			if re.search("^192\.0\.2\.", a): return True
			if re.search("^192\.88\.99\.", a): return True
			if re.search("^192\.168\.", a): return True
			if re.search("^198\.1[89]\.", a): return True
			if re.search("^198\.51\.100\.", a): return True
			if re.search("^203\.0\.113\.", a): return True
			if re.search("^2(2[4-9]|3[0-9])\.", a): return True
			if re.search("^^2(4[0-9]|5[0-5])\.", a): return True
		else:
			# Is DNS Name
			return False
	except:
		debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)

	return False

### Reverse DNS query (IP -> PTR)
def reversedns(ip, id=None):
	global usedns
	debug("reversedns(\"%s\")" % (ip), LOG_DEBUG, id=id)

	if not usedns:
		debug("NO DNS Module loaded", LOG_INFO, id=mail["id"])
		return None
	if isprivate(ip):
		debug("* reversedns(\"%s\") = Private network" % (ip), LOG_DEBUG, id=id)
		return None

	a = ip.split('.')
	if len(a) != 4: return None
	try:
		ptr = None
		if DNS.defaults['server'] == []: DNS.DiscoverNameServers()
		a.reverse()
		b = '.'.join(a)+'.in-addr.arpa'
		if DNS.DnsRequest(b, qtype = 'ptr').req().header['status'] == "NOERROR":
			ptr=DNS.DnsRequest(b, qtype = 'ptr').req().answers[0]['data']
	except IndexError:
## Sometimes no PTR on IP = "list index out of range"
		ptr = None
		pass
	except:
## Reason for exception is usually timeout, ignore
		debug("DNS query problems. %s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
		debug("* reversedns(\"%s\")" % (ip), LOG_ERR, id=id)
		pass

	debug("\tPTR reply: %s" % (ptr), LOG_DEBUG, id=id)
	return ptr

### Generate ip:from:to stings
def makeipfromto(mail):
	if conf["main"]["timeme"] is True: timer = timeme()
	debug("makeipfromto()", LOG_DEBUG, id=mail["id"])

	if mail.has_key("ipfromto"): return

	mail["ipfromto"] = { "raw": "",}
	for to in mail["to"]:
		mail["ipfromto"][to] = []
		for rec in mail["received"]:
			if mail["received"][rec].has_key("dns") and mail["received"][rec]["dns"]:
				tmp = "%s:%s" % (mail["received"][rec]["dns"],mail["from"][0])
				if tmp not in mail["ipfromto"][to]:
					debug("\tAppend (dns) %s" % (tmp), LOG_DEBUG+1, id=mail["id"])
					mail["ipfromto"][to].append(tmp)
					mail["ipfromto"]["raw"] += "%s:%s\n" % (tmp,to)
			if mail["received"][rec].has_key("ip"):
				tmp = "%s:%s" % (mail["received"][rec]["ip"],mail["from"][0])
			if tmp not in mail["ipfromto"][to]:
				mail["ipfromto"][to].append(tmp)
				mail["ipfromto"]["raw"] += "%s:%s\n" % (tmp,to)
				debug("\tAppend (ip) %s" % (tmp), LOG_DEBUG+1, id=mail["id"])
# NOTE! If there is SEVERAL recipients, use only FIRST to create ipfromto
#		break

#	for rec in mail["received"]:
#		for to in mail["to"]:
#			if mail["received"][rec].has_key("dns") and mail["received"][rec]["dns"]:
#				tmp = "%s:%s:%s" % (mail["received"][rec]["dns"],mail["from"][0],to)
#				if tmp not in mail["ipfromto"]:
#					debug("\tAppend %s" % (tmp), LOG_DEBUG, id=mail["id"])
#					mail["ipfromto"].append(tmp)
#
#			tmp = "%s:%s:%s" % (mail["received"][rec]["ip"],mail["from"][0],to)
#			if tmp not in mail["ipfromto"]:
#				mail["ipfromto"].append(tmp)

#	print show_vars(mail["ipfromto"])
	return

def strcleanup(str, id=None):
	if conf["main"]["timeme"] is True: timer = timeme()
	debug("*strcleanup()", LOG_INFO, id=id)
	str = re.sub("&Aring;|&#197;|&#xC5;", "Å", str)
	str = re.sub("&Auml;|&#196;|&#xC4;", "Ä", str)
	str = re.sub("&Ouml;|&#214;|&#xD6;", "Ö", str)

	str = re.sub("&aring;|&#229;|&#xE5;|Å", "å", str)
	str = re.sub("&auml;|&#228;|&#xE4;|Ä|�", "ä", str)
	str = re.sub("&ouml;|&#246;|&#xF6;|Ö|�", "ö", str)

	str = re.sub("&gt;|&#62;|&#x3E;", ">", str)		#>
	str = re.sub("&lt;|&#60;|&#x3C;", "<", str)		#<
	str = re.sub("&nbsp;|&#160;|&#xA0;", " ", str)		#
	str = re.sub(" ?(&euro;|&#8364;)", "€", str)		#€
	str = re.sub("&copy;|&#169;|&#xA9;", "(c)", str)	#(c)
	str = re.sub("&ndash;|&hypen;", "-", str)		#-
	str = re.sub("&acute;", "", str)			#'
	str = re.sub("&quot;|&[rl][ads]quo;", "", str)		#"
	str = re.sub("&amp;|&#38;|&#x26;", "&", str)		#&
	str = re.sub("&hellip;", "...", str)			#...
	str = re.sub("\\\\'", "\'", str)			#\\' -> \'
	str = re.sub('\\\\"', '\"', str)			#\\" -> \"
	return str

def html_strip(htmlstr, id=None):
	if conf["main"]["timeme"] is True: timer = timeme()
	debug("*html_strip()", LOG_INFO, id=id)
	htmlstr = oneliner(htmlstr)
	htmlstr = re.sub("<style.*?</style>", " ", htmlstr)
	htmlstr = re.sub("<font (color=.*? )?size=(\")?1(\")?>.*?</font>\n", "", htmlstr)
#	htmlstr = re.sub("<DIV>.*?</DIV>\n", "", htmlstr)
	htmlstr = re.sub("<.+?>", " ", htmlstr)
	htmlstr = re.sub(" + ", " ", htmlstr)

#	try:
#DBG# - I think that HTML stripper is not working?
#		nohtml=HTMLStripper()
#		htmlstr = "foobar"
#		nohtml.feed(htmlstr)
#		nohtml.close()
#	except:
#		print "excepted"
#		print("%s: %s" % (sys.exc_type, sys.exc_value))
	if conf["main"]["timeme"] is True: timer = timeme()
#	return (re.sub("\(image\)", "", re.sub("\xa0", "", nohtml.gettext())), nohtml.anchorlist)
	return htmlstr

# Strip character that can't print
def stripUnprintable(input_string, id=None):
#	debug("stripUnprintable()", LOG_DEBUG, id=id)
	try: filterUnprintable = stripUnprintable.filter
	except AttributeError: # only the first time it is called
		allchars = maketrans('','')
		delchars = allchars.translate(allchars, letters+digits+punctuation+whitespace)
		filterUnprintable = stripUnprintable.filter = lambda input: input.translate(allchars, delchars)
	return filterUnprintable(input_string)

# Make multiline strings as one long string
def oneliner(value, id=None):
	return re.sub(" + ", " ", re.sub("[\r\n\t]", " ", value))

def is_listed(needle,heystack,flags=re.IGNORECASE+re.MULTILINE,id=None,debugval=LOG_DEBUG):
	if len(heystack) > 30: hs = oneliner(heystack[0:27])+"..."
	else: hs = oneliner(heystack)
	if len(needle) > 30: ns = oneliner(needle[0:27])+"..."
	else: ns = oneliner(needle)
	debug("%s(needle=\"%s\", heystack=\"%s\", id=%s)" % (sys._getframe().f_code.co_name, ns, hs, id), debugval+1, id=id)
	try:
		if not needle or not heystack or len(needle) < 1 or len(heystack) < 1: return (None, 0)
	except:
		return (None, 0)
	tmp = False
	loops = 0

	if type(needle) is int: needle = [str(needle)]
	elif type(needle) is str:
		needle = needle.splitlines()
		try: needle.remove("")
		except: pass
		if type(needle) is str: needle = [needle]

	if type(heystack) is str: heystack=[heystack]
	for h in heystack:
		if len(h) > 30: hs = oneliner(h[0:27])+"..."
		else: hs = oneliner(h)
		for n in needle:
			if type(n) is tuple: n=n[0]
			if len(n) > 30: ns = oneliner(n[0:27])+"..."
			else: ns = oneliner(n)
			loops += 1
			debug("%s(needle=\"%s\", heystack=\"%s\", id=%s)" % (sys._getframe().f_code.co_name, ns, hs, id), debugval+2, id=id)
# Any possibility for direct hit?
			if n == h or n in h:
				debug("\tDirect hit: %s" % (n), debugval, id=id)
# TODO: We need to use 'default' action
				return (True, loops, n)
			try:
				tmp = re.search(n, h, flags)
			except:
				debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
				debug("FAILED: is_listed(%s, %s)" % (h[0:60], n[0:60]), LOG_ERR, id=id)
				continue
			if tmp:
# We got regexp match, now parse it
				retval = True
				debug("\tRegex %s: %s" % (loops, n), debugval+1, id=id)
				debug("\tRegex match %s-%s as: %s" % (tmp.span()[0], tmp.span()[1], tmp.group()), debugval+1, id=id)
				if tmp.groupdict(): debug("\tRegex keys: %s" % (tmp.groupdict()), debugval+1, id=id) # {"name": 'value'} ... for (?P<name>value.*)
# Do we have comment on front if regexp rule?
				comment = re.search("^\(\?#.*?\)", n)
				if comment:
					retval = comment.group()[3:-1]
				return (retval, loops, n, tmp.group(), tmp.groupdict())
	return (False, loops)

##############################################################################
### Basic fileoperations and other tools (Usualy we don't need to care if it
### success or not)
# Checked 19.2.2017, - Semi
def rm(file, id=None):
	debug("rm(\"%s\")" % (file), LOG_DEBUG, id=id)
	try:
		if os.path.exists(file): os.remove(file)
	except:
		pass
	return

# Checked 19.2.2017, - Semi
def rmdir(path, id=None):
	debug("rmdir(\"%s\")" % (path), LOG_DEBUG, id=id)
	try:
		os.rmdir(path)
	except OSError, (errno, strerror):
		if errno != 39: debug("%s" % sys.exc_value, LOG_ERR)
	except:
		debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
	return

# Checked 19.2.2017, - Semi
def mkdir(path, id=None):
	debug("mkdir(\"%s\")" % (path), LOG_DEBUG, id=id)
	try:
		os.makedirs(path, 0770)
	except OSError, (errno, strerror):
		if errno != 17: debug("%s" % sys.exc_value, LOG_ERR)
	except:
		debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
	return

# Checked 19.2.2017, - Semi
def mv(what, where, id=None):
	debug("mv(\"%s\" \"%s\")" % (what, where), LOG_DEBUG, id=id)
	try:
		os.rename(what, where)
	except:
		try:
			fpin = open(what,"r")
			fpout = open(where,"w+b")
			while 1:
				buf = fpin.read(1024*16)
				if len(buf) == 0: break
				fpout.write(buf)
			fpin.close()
			fpout.close()
			rm(what)
		except:
			debug("move failed: %s -> %s" % (what, where), LOG_ERR)
	return

# Checked 22.2.2017, - Semi
def rmpid(fname):
	debug("rmpid(\"%s\")" % (fname), LOG_DEBUG)
	if not os.path.exists(fname):
		debug("PID file %s missing!" % fname, LOG_WARNING)
		return True

	fp = open(fname, "r")
	pid=int(fp.readline().strip())
	fp.close
	if pid != os.getpid():
		debug("PID file %s is not ours!" % fname, LOG_WARNING)
		return False

	debug("Removing pid %s" % fname, LOG_NOTICE)
	rm(fname)
	return True

# Checked 22.2.2017, - Semi
def makepid(fname):
	debug("makepid(\"%s\")" % (fname), LOG_DEBUG)

	if os.path.exists(fname):
		fp = open(fname, "r")
		pid=int(fp.readline().strip())
		fp.close

		if os.path.exists("/proc/%d" % pid):
			fp = open("/proc/%d/stat" % pid, "r")
			pidstat = fp.readline().strip().split(" ")
			fp.close
			if pidstat[2] == "S": pidstat[2] = "Sleeping"
			elif pidstat[2] == "R": pidstat[2] = "Running"
			elif pidstat[2] == "T": pidstat[2] = "Stopped"
			debug("PID file %s found for process %s (%s)." % (conf["main"]["pid"], pidstat[1][1:-1], pidstat[2]), LOG_EMERG)
			return False
		else:
			debug("Stale PID file %s found. Removing." % (conf["main"]["pid"]), LOG_WARNING)
			rm(fname)
	try:
		debug("Create pid %s" % fname, LOG_NOTICE)
		fp = open(fname, "w+b")
		fp.write("%s\n" % os.getpid())
		fp.close()
	except:
##		return ("Error", sys.exc_value)
		debug("Couldn't create %s: %s" % (conf["main"]["pid"], tmp[1]), LOG_CRIT)
		return False
	return True

# Remove duplicates from sequence
# Checked 15.3.2017, - Semi
def uniq(seq, idfun=None):
	## order preserving
	if idfun is None:
		def idfun(x): return x
	seen = {}
	result = []
	for item in seq:
		if item == None: continue
		marker = idfun(item)
		# in old Python versions:
		# if seen.has_key(marker)
		# but in new ones:
		if marker in seen: continue
		seen[marker] = 1
		result.append(item)
	return result

##############################################################################
###
### SpamMilter Class
###
class SpamMilter(Milter.Milter):
	def __init__(self):
		self.id = Milter.uniqueID()
		debug("SpamMilter.__init__()", LOG_DEBUG, id=self.id)
		self.mail = maildef()
		self.mail["id"] = self.id

		try:
			self.tmpname = "%08d.tmp" % (self.id)
## Temp file in DISK
			if not os.path.exists(conf["main"]["tmpdir"]): mkdir(conf["main"]["tmpdir"])
			self.mail["tmpfile"] = conf["main"]["tmpdir"]+"/"+self.tmpname
			self.tmp = open(self.mail["tmpfile"],"w+b")
			debug("tmpfile: %s" % (self.mail["tmpfile"]), LOG_DEBUG, id=self.id)
		except IOError, (errno, strerror):
			debug("Temp file failure (%s: %s)" % (errno, strerror), LOG_DEBUG, id=self.id)
		except:
			debug("Temp file (%s) failure" % "%s/%s" % (conf["main"]["tmpdir"], self.tmpname), LOG_DEBUG, id=self.id)
		return

	def _cleanup(self):
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter._cleanup()", LOG_DEBUG, id=self.id)
		if self.tmp:
			self.tmp.close()
			rm(self.tmp.name, id=self.id)
		if not self.mail:
			return

		if conf["main"]["crcsave"] and self.mail.has_key("checksum"):
			crc = self.mail["checksum"]
			# New entry
			if not msgbase.has_key(crc):
				msgbase[crc] = msgtemplate.copy()
				msgbase[crc]["firstseen"] = timeme()
			msgbase[crc]["seen"] += 1
			msgbase[crc]["lastseen"] = timeme()

#			try:
#				save_vars(msgbase, conf["main"]["crcfile"])
#			except:
# Saving CRC file failed
#				debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)

#			if self.mail["action"][0] in ['reject','delete','discard','block']:
#				msgbase[crc]['block'] += 1
#			elif self.mail["action"][0] in ['flag','warn']:
#				msgbase[crc]['flag'] += 1
#			else:
#				msgbase[crc]['pass'] += 1


#				print "#############################################################################"
#				print "Received:",
#				for rec in self.mail["received"]:
#					print "\n\t",
#					if self.mail["received"][rec].has_key("dns"):
#						print "%s" % (self.mail["received"][rec]["dns"]),
#					print " [%s]" % (self.mail["received"][rec]["ip"]),
#					if self.mail["received"][rec].has_key("helo"):
#						print " (%s)" % (self.mail["received"][rec]["helo"]),
#				print """
#
#ID:\t\t%s
#Mail From:\t%s
#From:\t\t%s
#Rcpt To:\t%s
#To:\t\t%s
#Subject:\t%s
#Size:\t\t%d
#Checksum:\t%s""" % (
#self.mail["id"],
#self.mail["from"][0],
#self.mail["header"]["From"],
#self.mail["to"],
#self.mail["header"]["To"],
#self.mail["subject"][0:80],
#self.mail["size"],
#self.mail["checksum"]
#)
#				if conf["main"]["crcsave"]:
#					print "\t\t", msgbase[self.mail["checksum"]]
#				print
#				tc = 0
#				print "%s\t\t%s\t%s\t%s" % ("Test", "Time", "Tests", "Action and why")
#				print "-----------------------------------------------------------------------------"
#				for t in self.mail["tests"]:
#					if self.mail["timer"].has_key(t):
#						print "%-15s %s\t" % (t, self.mail["timer"][t]),
#					else:
#						print "%-15s %s\t" % ("", ""),
#					print "%5d\t" % (self.mail["tests"][t]),
#					tc += self.mail["tests"][t]
#					if self.mail["result"].has_key(t):
#						if self.mail["result"][t] != None:
#							print "%s\t" % (self.mail["result"][t][0]),
#							print "%s" % (oneliner(self.mail["result"][t][1][0:80])),
#						else:
#							print "",
#					print
#				print "-----------------------------------------------------------------------------"
#				print "%s\t\t%s\t" % ("TOTAL:", self.mail["timer"]["timepass"]),
#				print "%5d\t" % (tc),
#				print "%s" % (self.mail["action"][0]),
#				print
#				print








##		if not conf["main"]["childs"]: Tcrc()
		if conf["main"]["timeme"]: self.mail["timer"]["SpamMilter_"+sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
		return

	def abort(self):
		debug("SpamMilter.abort()", LOG_DEBUG, id=self.id)
		self._cleanup()
		return CONTINUE

	def close(self):
		debug("SpamMilter.close()", LOG_DEBUG, id=self.id)
		self._cleanup()
		return CONTINUE

	def connect(self,host,family,hostaddr):
		if conf["main"]["timeme"]: self.mail["timer"]["passthru"] = timeme()
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.connect(%s, %s)" % (host,hostaddr), LOG_DEBUG, id=self.id)
# Crashes if IPV6 / SEMI
# I have no active IPv6, so we need to think how we can replicate and fix
# this.
		self.mail["received"][1]["ip"] = hostaddr[0]
		if usedns:
			self.mail["received"][1]["dns"] = reversedns(hostaddr[0], id=self.id)

		if conf["main"]["timeme"]: self.mail["timer"]["smtp_"+sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
		return CONTINUE

	def hello(self,host):
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.hello(%s)" % (host), LOG_DEBUG, id=self.id)

		self.mail["received"][1]["helo"] = host
# 2DO		self.reuse = self.mail["received"][1]
		if conf["main"]["timeme"]: self.mail["timer"]["smtp_"+sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
		return CONTINUE

	def envfrom(self,mailfrom,*vars):
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.envfrom(\"%s\", %s)" % (mailfrom,vars), LOG_DEBUG, id=self.id)

### TODO ###
		if not self.mail:
		# This could be triggered after eom, and self.mail COULD be set.. need to rethink.
		#	self._cleanup()
			debug("Connection reused", LOG_DEBUG, id=self.id)
		#	self.__init__()
		#	self.mail["received"][1] = self.reuse
		#	self.mail["smtpcmds"].append("reused")

		debug("mail from:%s" % (mailfrom), LOG_DEBUG, id=self.id)
		if mailfrom in ["<>", "", None]:
			if self.mail["received"][1].has_key("dns"):
				mailfrom = "<MAILER-DAEMON@%s>" % (self.mail["received"][1]["dns"])
			else:
				mailfrom = "<MAILER-DAEMON@[%s]>" % (self.mail["received"][1]["ip"])
		self.mail["from"] = parse_addrs(mailfrom, id=self.id)

### TODO ###
		#if not conf["runtime"]["offline"]:
		#	self.mail["my"]["ip"] = self.getsymval('{if_addr}')
		#	self.mail["my"]["dns"] = self.getsymval('{if_name}')
		#	if self.getsymval('{auth_type}'):
		#		self.mail["smtp_auth"] = self.getsymval('{auth_authen}')

		if conf["main"]["timeme"]: self.mail["timer"]["smtp_"+sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
		return CONTINUE

	def envrcpt(self,rcpt,*vars):
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.envrcpt(\"%s\")" % (rcpt), LOG_DEBUG, id=self.id)

		if len(self.mail["to"]) > 0 and rcpt not in self.mail["to"]:
			self.mail["to"].append(parse_addrs(rcpt, id=self.id)[0])
		else:
			self.mail["to"] = parse_addrs(rcpt, id=self.id)

		if conf["main"]["timeme"]: self.mail["timer"]["smtp_"+sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
		return CONTINUE

	def header(self,field,value):
		if not self.mail["timer"].has_key("smtp_header") and conf["main"]["timeme"]: self.mail["timer"]["smtp_header"] = timeme()
		debug("SpamMilter.header(%s, %s)" % (field,value), LOG_DEBUG+1, id=self.id)

		lfield = field.lower() # Lower case field name
### Headers to drop ... just proof-of-concept
		if lfield in [ "x-spambayes-classification", "x-spam-level", "mime-version"]:
			return CONTINUE

		if len(self.mail["header"]) == 0:
			self.mail["size"] = 0
			self.mail["subject"] = {}
			self.mail["header"]["raw"] = ""
			if self.tmp:
				self.tmp.write("From %s %s\n" % (self.mail["from"][0], time.ctime()))
		else:
			if self.tmp:
				self.tmp.write("%s: %s\n" % (field, value))

### Note, this is NOT endless loop, it is just used like switch-case
### statement.  We break out when perferred line has been processed.
### Save header line as is, before prosessing.
### This is just lazy way to do "elif"
		while 1:
			oneline_value = oneliner(value, id=self.id).strip()

			if self.mail["header"].has_key(field) and lfield not in [ "subject", "received" ]:
				if self.mail["header"][field] == oneline_value: break
				if type(self.mail["header"][field]) is not list:
					tmp = self.mail["header"][field]
					del self.mail["header"][field]
					self.mail["header"][field] = [ tmp ]
				self.mail["header"][field].append(oneline_value)
			elif lfield not in [ "received" ]:
				self.mail["header"][field] = oneline_value

			if lfield == "received":
				recstr="(from (?P<helo>\S+) \((((?P<dns>\S+) )?\[((?P<ip>[\d\.]+)|ipv6:(?P<ipv6>[\w\d:]+))\]|[\w\d, ]+)\) )?(using .+ )?by (?P<by>\S+)( \([\S ]+\))?( with (?P<proto>\S+( [\d\.]+)?))?( id (?P<id>\S+))?( for <(?P<for>\S+)>)?( \([\S ]+\))?; (?P<date>.+)"
				a = re.compile(recstr).match(oneline_value.lower())

				if not a:
					debug("Can't parse received: %s" % (oneline_value.lower()), LOG_INFO, id=self.id)
					break
				b={k: v for k, v in a.groupdict().items() if v}
				if b.has_key("dns") and b["dns"][-1] == ".":
					b["dns"] = b["dns"][:-1]

				# Do not add received line if host is localhost or inside (any) private network
				# We have no need to follow internal relaying?
#				if (b.has_key("ip") and islocal(b["ip"])): break
				if (b.has_key("ip") and isprivate(b["ip"])) or (b.has_key("dns") and isprivate(b["dns"])): break

				# Populate mail data with received host information
				reclen = len(self.mail["received"])
				if (b.has_key("by") and self.mail["received"][reclen].has_key("by")) and b["by"] == self.mail["received"][reclen]["by"]:
					break
				self.mail["received"][reclen+1]=b

			# /received
				break

			self.mail["header"]["raw"] += "%s: %s\n" % (field, oneline_value)

			if lfield == "subject":
				self.mail["subject"]["raw"] = oneline_value
			# /subject
				break

# NOTE! Don't remove this last break, without this we are in infinite loop :)
		# /while 1
			break
		return CONTINUE

	def eoh(self):
		debug("SpamMilter.eoh()", LOG_DEBUG, id=self.id)
## Received fix was here. Also it would be safe to do ipfromtopre, ipfromto, dyndns, rbl, headers test here.

# Do PTR DNS requests
		for val in self.mail["received"]:
			if self.mail["received"][val].has_key("ip") and not self.mail["received"][val].has_key("dns"):
				self.mail["received"][val]["dns"] = reversedns(self.mail["received"][val]["ip"], id=self.id),

		if conf["main"]["timeme"] and self.mail["timer"].has_key("smtp_header"):
			self.mail["timer"]["smtp_headers"] = str("%.4f") % timeme(self.mail["timer"]["smtp_header"])
			del self.mail["timer"]["smtp_header"]

# Create ip-from-to strings
		makeipfromto(self.mail)

		return CONTINUE

	def body(self,chunk):
		global UseSHA

		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.body() (chunk size: %d)" % len(chunk), LOG_DEBUG, id=self.id)

		if self.tmp and self.mail["size"] == 0:
			self.tmp.write("\n")

## Make SHA checksum only for first chunk of message, maximum size of chunk
## seems to be 65535.  So if first 64K bytes of message is same, this can
## cause problems.  But if you think about possibility of different message
## with with same 64K?  Unlikely.

## For python > 2.4
			if UseSHA > 24:
				self.mail["checksum"] = hashlib.sha1(chunk).hexdigest()
				debug("hashlib.sha1: %s" % (self.mail["checksum"]), LOG_DEBUG, id=self.id)
## For Python >= 2.4
			elif UseSHA > 0:
				self.mail["checksum"] = sha.new(chunk).hexdigest()
				debug("sha.new: %s" % (self.mail["checksum"]), LOG_DEBUG, id=self.id)

		self.mail["size"] += len(chunk)
		self.mail["raw"] += chunk
		if self.tmp: self.tmp.write(chunk)

		if conf["main"]["timeme"]: self.mail["timer"]["smtp_"+sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
		return CONTINUE

	def eom(self):
### EOM is called as end of SMTP commands, after client has submited body of
### message.  Now we should have all data there is.  It is time to look what
### we have...
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.eom()", LOG_DEBUG, id=self.id)
		if conf["main"]["timeme"]: self.mail["timer"]["smtp_"+sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)

### What if Domain (not) found from filtered list
		tests = None
		rules = None
		self.mail["todomain"] = self.mail["to"][0].split("@")[1]
		try:
			if conf["runtime"]["args"]["tests"]:
				tests=conf["runtime"]["args"]["tests"][0].split(',')
			else:
				debug("Checking for filtered domains", LOG_DEBUG, id=self.id)
				for a in conf["filter"]["domains"]:
					if is_listed(a[0], self.mail["todomain"], id=self.mail["id"]):
						tests=a[1]
						break

			debug("Looking for domain rules", LOG_DEBUG, id=self.id)
			for a in conf["filter"]["rules"]:
				if is_listed(a[0], self.mail["todomain"], id=self.mail["id"]):
					rules=a[1]
					break
		except:
			debug("FAILED %s(): Check if recipient domain configured for filtering" % (sys._getframe().f_code.co_name), LOG_ERR, id=self.mail["id"])
			debug("EXCEPTION: %s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR, id=self.id)
			# EMERGENCY EXIT HERE?

		if not tests:
			debug("\tskip, not filtered domain", LOG_DEBUG, id=self.id)
			return Milter.CONTINUE

		if self.mail["size"] == 0 and self.mail["subject"] == "":
			self.mail["type"] = "empty"
			return Milter.DISCARD
		self.mail["subject"] == "(none)"

		debug("\tTests: %s" % (tests), LOG_DEBUG, id=self.id)
		self.mail["tests"] = tests
		debug("\tRules: %s" % (rules), LOG_DEBUG, id=self.id)
		self.mail["rules"] = rules

# End eom() timer here
		if conf["main"]["timeme"]: self.mail["timer"]["smtp_"+sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)

#		try:
		if 1:
			if self.tmp:
				self.tmp.seek(0)
				msg = message_from_file(self.tmp)
#				self.mail["raw"] = """%s""" % msg
				(self.mail["subject"]["txt"], subchar) = decode_header(msg["subject"])[0]
				charset = msg.get_charsets()
				if subchar: charset.append(subchar)
				self.mail["charset"]=uniq(charset)

#				self.mail["mime"] = mimepart(msg, id=self.id)
#				print show_vars(self.mail["mime"])
#				print show_vars(dir(msg))
#				print show_vars(msg)
#		except:
#			debug("eom() EXCEPTION: %s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR, id=self.id, trace=False)
			try:
				if self.tmp: self.tmp.close()
			except:
				pass
#			try: self.setreply("421", "4.2.1", "Error while parsing MIME structre of message, try again.")
#			except: pass
##			return Milter.REJECT
# Save for debug
#				mv(self.tmp.name, "/tmp/%s" % (self.tmpname))
#				save_vars(self.mail, "/tmp/%s.var" % (self.tmpname), id=self.mail["id"]);
#				debug("saved as /tmp/%s" % (self.tmpname), LOG_ERR, id=self.id, trace=False)
#			return Milter.CONTINUE

# NOTE! We may don't have self.mail if message was aborted. We need exception handling on that.
###
### Now message is received and processed. Fun part begins now, testing.
###
		if conf["main"]["timeme"]: timer = timeme()
		self.mail["result"] = {}
		self.mail["action"] = []
		self.mail["tests_done"] = []

		for test in tests:
			if not globals().has_key("test_"+test):
				debug("Test function test_%s does not exist" % (test), LOG_ERR, id=self.id)
				continue

			ret = eval("test_"+test)(self.mail)
			self.mail["tests_done"].append(test)
			if ret:
				self.mail["result"][test] = ret
				if type(ret) is bool:
					if conf["actions"].has_key(test): ret = conf["actions"][test]
# This is our 'master default' for any match
					else: ret = ("flag")
				if ret[0]:
					action=ret[0].lower()
					if ret[2]: ret_regex=ret[2]
					else: ret_regex = None
					if ret[3]: ret_match=ret[3]
					else: ret_match = None
					if action in ['break']: continue
					if (ret[0][0] in ['-']) or (ret[0][-1] in ['-']):
						print "Marker found"
						debug("\t\tflag with - ... keep testing", LOG_DEBUG, id=self.id)
						continue
#				if ret and (ret[0].lower() in ['flag', 'reject', 'delete', 'block', 'discard', 'accept', 'ignore']):
#					debug("Testing hit found, break testing", LOG_DEBUG, id=self.id)
#					break
#				if ret and ret[0].lower() in ['authmx', 'skip', 'break']:
#					self.mail["action"].insert(0, ret[0].lower())

###
### Tests done, now we should know what to do
###
		if conf["main"]["timeme"]: self.mail["timer"]["all_tests"] = str("%.4f") % timeme(timer)
# self.mail["tests"]		Tests need to be executed for domain
# self.mail["tests_done"]	Tests executed
# self.mail["rules"]		Special handling rules for domain














		if conf["main"]["timeme"]: self.mail["timer"]["passthru"] = str("%.4f") % timeme(self.mail["timer"]["passthru"])
# Timing information
#		print "Timer:", show_vars(self.mail["timer"])
#		print "Result:", show_vars(self.mail["result"])
		del self.mail["raw"]
		del self.mail["header"]["raw"]
		del self.mail["ipfromto"]["raw"]
		if conf["runtime"]["args"]["showmail"]:
			print "mail:",
			print show_vars(self.mail)
		return CONTINUE

##############################################################################
###
### Define tests
###
# Checked 17.3.2017, - Semi
def test_connect(mail):
# Rework
	if conf["main"]["timeme"]: timer = timeme()
	debug("%s()" % (sys._getframe().f_code.co_name), LOG_DEBUG, id=mail["id"])

	res = None
	seen = []
	loops = 0
	if islocal(mail["received"][1]["ip"]):
		debug("\tSender is local (me)", LOG_DEBUG, id=mail["id"])
		loops += 1
	else:
		for rec in mail["received"]:
			if not res and mail["received"][rec].has_key("ip"):
				val = mail["received"][rec]["ip"]
				if val not in seen:
					seen.append(val)
					debug("\tConnect from %s" % (val), LOG_INFO, id=mail["id"])
					res = is_listed(conf["rules"]["connect"], val, id=mail["id"])
# Note! Reverse DNS should not be trusted, I have seen that people assign 'localhost' for IP.
# If there is "localhost" as accepted in connect rules, they will get past this.
# Maybe we should do reverse check? So IP and DNS matches.
			if not res and mail["received"][rec].has_key("dns"):
				val = mail["received"][rec]["dns"]
				if val not in seen:
					seen.append(val)
					debug("\tConnect from %s (dns)" % (val), LOG_INFO, id=mail["id"])
					res = is_listed(conf["rules"]["connect"], val, id=mail["id"])
# I don't think that we should look if 'helo' is on connect rules
#			if not res and mail["received"][rec].has_key("helo"):
#				val = mail["received"][rec]["helo"]
#				if val not in seen:
#					seen.append(val)
#					debug("\tConnect from %s (helo)" % (val), LOG_INFO, id=mail["id"])
#					res = is_listed(conf["rules"]["connect"], val, id=mail["id"])
			if res: loops += res[1]
			if res and res[0]:
				break
## break for NOT to be RECURSIVE (Should it be? or not?)
#			break

	if conf["main"]["timeme"]: mail["timer"][sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
	return res

# Checked 17.3.2017, - Semi
def test_helo(mail):
# Rework
	if conf["main"]["timeme"]: timer = timeme()
	debug("%s()" % (sys._getframe().f_code.co_name), LOG_DEBUG, id=mail["id"])

	res = None
	seen = []
	for rec in mail["received"]:
		if not res and mail["received"][rec].has_key("helo"):
			helo = mail["received"][rec]["helo"]
			if helo not in seen:
				seen.append(helo)
				debug("\tHelo %s" % (helo), LOG_INFO, id=mail["id"])
			if mail.has_key("my"):
# Is HELO My IP?
				if mail["my"].has_key("ip") and helo == mail["my"]["ip"]:
					debug("\t\t%s = %s (my ip)" % (helo, mail["my"]["ip"]), LOG_DEBUG, id=mail["id"])
					res = True
# Is HELO My DNS?
				elif mail["my"].has_key("dns") and helo == mail["my"]["dns"]:
					debug("\t\t%s = my dns" % (helo), LOG_DEBUG, id=mail["id"])
					res = True
# or is HELO domain name of recipient?
				elif mail.has_key("todomain") and helo == mail["todomain"]:
					debug("\t\t%s = todomain" % (helo), LOG_DEBUG, id=mail["id"])
					res = True
			if not res:
				res = is_listed(conf["rules"]["helo"], helo, id=mail["id"])
			if res:
				break
# Sorry, not recursive
		break

	if conf["main"]["timeme"]: mail["timer"][sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
	return res

# Checked 15.3.2017, - Semi
def test_ipfromtopre(mail):
	if conf["main"]["timeme"]: timer = timeme()
	debug("%s()" % (sys._getframe().f_code.co_name), LOG_DEBUG, id=mail["id"])
	res = is_listed(show_vars(conf["rules"]["ipfromtopre"]), mail["ipfromto"]["raw"], id=mail["id"])

	if conf["main"]["timeme"]: mail["timer"][sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
	return res

# Checked 15.3.2017, - Semi
def test_ipfromto(mail):
	if conf["main"]["timeme"]: timer = timeme()
	debug("%s()" % (sys._getframe().f_code.co_name), LOG_DEBUG, id=mail["id"])
	res = is_listed(show_vars(conf["rules"]["ipfromto"]), mail["ipfromto"]["raw"], id=mail["id"])
	if conf["main"]["timeme"]: mail["timer"][sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
	return res

# Checked 18.3.2017, - Semi
def test_crc(mail):
	if conf["main"]["timeme"]: timer = timeme()
	debug("%s()" % (sys._getframe().f_code.co_name), LOG_DEBUG, id=mail["id"])
	if not conf["main"]["crcsave"] or not mail.has_key("checksum"): return None

# Todo: Configuration rule, crcremove. For regexp patterns to remove from
# mail body before counting CRC, so email addresses and other 'variable'
# data can be removed from mail.
	if msgbase.has_key(mail["checksum"]):
		debug("\t%s found from CRC base" % mail["checksum"], LOG_DEBUG, id=mail["id"])

		crc=mail["checksum"]
# Maybe this should be configurable?
		if timeme(msgbase[crc]['lastseen']) < conf["main"]["crchours"]*60*60:
# If mesage is BLOCKED more then FIVE times in CRCHOURS
			if msgbase[crc]['block'] > 5:   res = ('flag', 1, ">5 block/%dh" % (conf["main"]["crchours"]))
# If mesage is BLOCKED more then ONE times in CRCHOURS
			elif msgbase[crc]['block'] > 1: res = ('flag', 1, ">1 block/%dh" % (conf["main"]["crchours"]))
# If mesage is FLAGGED more then FIVE times in CRCHOURS
			elif msgbase[crc]['flag'] > 5:  res = ('flag', 1, ">5 flag/%dh" % (conf["main"]["crchours"]))
# If mesage is FLAGGED more then ONE times in CRCHOURS
			elif msgbase[crc]['flag'] > 1:  res = ('flag', 1, ">1 flag/%dh" % (conf["main"]["crchours"]))
		else:
			debug("\t%s is older then %dh" % (crc, conf["main"]["crchours"]), LOG_DEBUG+1, id=mail["id"])

	if conf["main"]["timeme"]: mail["timer"][sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
	return None

def test_dyndns(mail):
	if conf["main"]["timeme"]: timer = timeme()
	debug("%s()" % (sys._getframe().f_code.co_name), LOG_DEBUG, id=mail["id"])

	for var in mail["received"]:
		if mail["received"][var].has_key("dns"):
			print mail["received"][var]["dns"]
			res = is_listed(show_vars(conf["rules"]["dyndns"]), mail["received"][var]["dns"], id=mail["id"])
			if res: break

	if conf["main"]["timeme"]: mail["timer"][sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
	return None

def test_rbl(mail):
	global usedns

	if conf["main"]["timeme"]: timer = timeme()
	debug("%s()" % (sys._getframe().f_code.co_name), LOG_DEBUG, id=mail["id"])

	if not usedns:
		debug("NO DNS Module loaded", LOG_INFO, id=mail["id"])
		return None

#	DNS.defaults['timeout'] = 1
#	if DNS.defaults['server'] == []: DNS.DiscoverNameServers()

	res = None
	failed = 0
	seen = []
	loops = 0

#	print show_vars(mail["received"])
	for var in mail["received"]:
		if mail["received"][var].has_key("ip"):
			if mail["received"][var]["ip"] in seen:
				continue
			debug("\t%s" % (mail["received"][var]["ip"]), LOG_DEBUG+1, id=mail["id"])
			seen.append(mail["received"][var]["ip"])
			a = split(mail["received"][var]["ip"], '.')
			a.reverse()

			if mail["received"][var].has_key("note"):
				print "Note:",mail["received"][var]["note"]

			for rbl in conf["settings"]["ipservers"]:
				if rbl[0:3] == "(?#":
					action = rbl[3:rbl.find(")")]
					rblserver = rbl[rbl.find(")")+1:]
				else:
					action = conf["actions"]["rbl"]
					rblserver = rbl
				debug("\tRBL: %s (if match %s)" % (rblserver, action), LOG_DEBUG+1, id=mail["id"])
				loops += 1
				b=join(a, '.')+'.'+rblserver
				try:
					q = DNS.DnsRequest(b, qtype = 'A').req()
					if q.header['status'] == "NOERROR":
						debug("\t\tA %s" % (q.answers[0]['data']), LOG_DEBUG+1, id=mail["id"])
						try:
							q = DNS.DnsRequest(b, qtype = 'TXT').req()
							if q.header['status'] == "NOERROR" and len(q.answers) > 0:
								debug("\t\tTXT %s" % (q.answers[0]['data']), LOG_DEBUG+1, id=mail["id"])
								res = (True, q.answers[0]['data'][0])
						except:
							pass
						if not res:
							debug("\t\tNo reason provided by TXT", LOG_DEBUG+1, id=mail["id"])
							res = (True, "BLACKLISTED from %s" % (rbl))
						break
				except:
## Reason for exception is usually timeout, ignore but report as debug information
					debug("test_rbl exception (DNS query) - %s: %s" % (sys.exc_type, sys.exc_value), LOG_INFO)
## If RBL was failed for some reason, wait for few seconds and continue after wait
					if failed < 3:
						time.sleep(1)
					else:
						self.mail["note"] = "DNS Failure for black list testing."
						break
					failed += 1
### Break on first RBL match
				if res: break
			if res: break

	print show_vars(mail["received"])
	if conf["main"]["timeme"]: mail["timer"][sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
#	print res
#	print loops
#	sys.exit(1)
	return res

# Checked 15.3.2017, - Semi
def test_headers(mail):
	if conf["main"]["timeme"]: timer = timeme()
	debug("%s()" % (sys._getframe().f_code.co_name), LOG_DEBUG, id=mail["id"])
	res = is_listed(conf["rules"]["headers"], mail["header"]["raw"], id=mail["id"])
	if conf["main"]["timeme"]: mail["timer"][sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
	return res

def test_wordscan(mail):
	if conf["main"]["timeme"]: timer = timeme()
	debug("%s()" % (sys._getframe().f_code.co_name), LOG_DEBUG, id=mail["id"])

	res = None
	action = None
	if not res and mail.has_key("raw"):
# NOTE! This may pass REALLY BIG values to is_listed
		if not res and conf["rules"].has_key("blockwords"):
			res = is_listed(conf["rules"]["blockwords"], mail["raw"], id=mail["id"])
		if not res and conf["rules"].has_key("wordscan"):
			res = is_listed(conf["rules"]["wordscan"], mail["raw"], id=mail["id"])
		if res and res[0]:
			action = res[0]
			matchre = res[2]
			matchstr = res[3]
	else:
		debug("\tMail does not have 'raw' part", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"]: mail["timer"][sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
	return res

# Checked 15.3.2017, - Semi
def test_samefromto(mail):
	if conf["main"]["timeme"]: timer = timeme()
	debug("%s()" % (sys._getframe().f_code.co_name), LOG_DEBUG, id=mail["id"])

	if isprivate(mail["received"][1]["ip"]): return None
	if mail["from"] == mail["to"]: return True

	if conf["main"]["timeme"]: mail["timer"][sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
	return (False, 1)

# Checked 17.3.2017, - Semi
def test_charset(mail):
	if conf["main"]["timeme"]: timer = timeme()
	debug("%s()" % (sys._getframe().f_code.co_name), LOG_DEBUG, id=mail["id"])

	res = None
	if mail.has_key("charset"):
		for val in mail["charset"]:
			res = is_listed(conf["rules"]["charset"], val, id=mail["id"])
			if res: break

	if conf["main"]["timeme"]: mail["timer"][sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
	return None

def test_bayesian(mail):
	if conf["main"]["timeme"]: timer = timeme()
	debug("%s()" % (sys._getframe().f_code.co_name), LOG_DEBUG, id=mail["id"])

	print "TODO: Bayesian scan should be done here"
	res = (None)

	if conf["main"]["timeme"]: mail["timer"][sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
	return res

##############################################################################
###
### Class for "manual" testing
###
class test:
#
# Variables needed in .var file
# "id" - ID Integer for message
# "received[1]" - First received entry. Needed to simulate 'connection' and 'helo'
# "from" for smtp 'mail from' command
# "to" for 'rcpt to' recipients
# "raw" as raw mail to get header and body data from
# "headers/raw" If body and headers are separated
#
	def __init__(self, file, verbose = None):
		if file.find(".") > 0:
			file=file[0:file.rfind(".")]
		if not os.path.exists(file):
			if os.path.exists("%s.var" % file):
				file = "%s.var" % file
			else:
				print "File %s not found!" % file
				sys.exit(2)

		# Load Configuration
		conf["runtime"]["offline"] = True
		Tconfig()
		# Setup our debugging
		conf["main"]["savedir"] = None
		conf["main"]["tmpdir"] = "."

		# Load mail from file with variables
		self.mail = maildef()
		conf["runtime"]["nodebug"] = True
		self.mail = load_mailvar(file)
		conf["runtime"]["nodebug"] = False

		# Open temp file and write raw message into it
		if self.mail.has_key("raw") and self.mail["raw"]:
			self.tmp = open("%s.tmp" % (file), "w+b")
			if self.mail.has_key("header") and self.mail["header"].has_key("raw"):
				self.tmp.write(self.mail["header"]["raw"])
				self.tmp.write("\n\n")
			self.tmp.write(self.mail["raw"])
			self.tmp.close()

			# Reopen tmp file as read-only and move to end
			# Now we should have system like when online
			self.tmp = open("%s.tmp" % (file), "r")
			#self.tmp.seek(0,2)	# Seek to end-of-file
			self.tmp.seek(0)	# Seek to begining-of-file

	def feed2milter(self):
		m = SpamMilter()

		m.mail["id"] = self.mail["id"]
		if self.mail.has_key("my"): m.mail["my"] = self.mail["my"]
		m.id = m.mail["id"]
		m.mail["tmpfile"] = "%08d.tmp" % (m.id)

		# Use data from variables, and simulate SMTP-connection.
		if not self.mail["received"][1].has_key("dns"):
			self.mail["received"][1]["dns"] = "[%s]" % self.mail["received"][1]["ip"]
# Connect
		m.connect(self.mail["received"][1]["dns"],None,[self.mail["received"][1]["ip"]])
		if self.mail["received"][1].has_key("helo"):
# Helo
			m.hello(self.mail["received"][1]["helo"])
		else:
			m.hello(self.mail["received"][1]["dns"])
		if type(self.mail["from"]) is list:
# Mail From
			m.envfrom("<%s>" % self.mail["from"][0])
		else:
			m.envfrom("<%s>" % self.mail["from"])
		if type(self.mail["to"]) is list:
			for r in self.mail["to"]:
# Rcpt to
				m.envrcpt("<%s>" % r)
		else:
			m.envrcpt("<%s>" % self.mail["to"])
		self.tmp.seek(0)
		oline=""

		while 1:
			line=self.tmp.readline()
			if line[0:5] == "From ": continue

			if line[0] == "\t" or line[0] == " ":
				oline = oline+line
				tabbed=True
				continue
			elif oline == "":
				oline=line
			else:
# Headers
				m.header(oline[0:oline.find(":")],oline[oline.find(":")+2:-1])
				oline=line
			if len(line) < 2: break
		m.eoh()
		# Feed maximum of 2MB of message to milter, should we increase this?
		if self.tmp:
# Data
			m.body(self.tmp.read(1024*1024*2))
		# Now we have done everything as in 'online'
		m.eom()
# Close
		m.close()
		if self.tmp:
			self.tmp.close()
			rm(self.tmp.name)

#		if conf["runtime"]["args"]["showmail"]:
#			print "mail:",
#			print show_vars(m.mail)
# "Client" data, this is message to be filtered (should be considered as 'read-only')
#			tmp = self.mail
#			del tmp["raw"]
#			print "self.mail:",
#			print show_vars(tmp)
		return

##############################################################################
###
### CHILD THREADS
###
def Tconfig(childname=None, silent=None):
	global conf, conffile

	debug("Tconfig(childname=%s)" % (childname), LOG_DEBUG)

	if conf["runtime"]["args"]["conf"]:
		conf["runtime"]["conffile"] = conf["runtime"]["args"]["conf"][0]
		if not os.access(conf["runtime"]["conffile"], os.R_OK):
			debug("FATAL: Can't access %s." % (conf["runtime"]["conffile"]), LOG_CRIT)
			sys.exit(2)

	if conf["runtime"]["conffile"] == None:
		files = [ ]
# Build array of possible configuration locations
		if conffile[0] != "/":
			files.append("%s/%s" % (conf["runtime"]["startdir"], conffile))
			if conf["runtime"]["bindir"] != conf["runtime"]["startdir"]:
				files.append("%s/%s" % (conf["runtime"]["bindir"], conffile))
			files.append("/etc/sspamm/%s" % conffile)
			files.append("/etc/%s" % conffile)
			files.append(None)
		cf = None
		for cf in files:
			if cf != None and os.access(cf, os.R_OK):
				break

		if cf == None:
			debug("FATAL: Can't find or read %s." % (conffile), LOG_EMERG)
			return
		conf["runtime"]["conffile"] = cf

	if childname: debug("Tconfig loop started", LOG_INFO)

	conf["runtime"]["endtime"] = 0
	while conf["runtime"]["endtime"] == 0:
		if not os.access(conf["runtime"]["conffile"], os.R_OK):
# If we can't read config file, we report it and wait for one minute. Maybe
# we should do some other emergency prosedure here?
			debug("FATAL: Can't access %s." % (conf["runtime"]["conffile"]), LOG_CRIT)
			time.sleep(60)
			continue
		if conf["runtime"]["conftime"] < os.stat(conf["runtime"]["conffile"])[8]:
			debug("Config file %s found." % conf["runtime"]["conffile"], LOG_INFO)
			if conf["runtime"]["conftime"] > 0:
				save_config(conf["runtime"]["conffile"])
			conf["runtime"]["conftime"] = os.stat(conf["runtime"]["conffile"])[8]
			conf["runtime"]["confpath"] = conf["runtime"]["conffile"][0:conf["runtime"]["conffile"].rfind("/")]

			if conf["runtime"]["conffile"].rfind("/") < 0:
				conf["runtime"]["confpath"] = "."
			else:
				conf["runtime"]["confpath"] = conf["runtime"]["conffile"][0:conf["runtime"]["conffile"].rfind("/")]
			if childname: debug("Configuration %s reloaded" % (conf["runtime"]["conffile"]), LOG_INFO)
			load_config(conf["runtime"]["conffile"])

			if not conf["runtime"]["offline"] and conf["main"]["savedir"]:
				try: mkdir(conf["main"]["savedir"])
				except: pass
		else:
			if childname and not (conf["main"]["pid"] and os.path.exists(conf["main"]["pid"])):
				debug("Pid file %s missing, quiting." % (conf["main"]["pid"]), LOG_NOTICE)
				conf["runtime"]["endtime"] = -1
# If threaded we can't return back because Milter.runmilter does not end.
				cleanquit()
				break
			else:
# Poll configuration file every 2 seconds
				time.sleep(2)
		if not childname: break
		time.sleep(1)
	if childname: debug("Config thread quited", LOG_INFO)
	return

## Thread to keep CRC database clean
def Tcrc(childname=None):
	global msgbase
	debug("Create CRC child thread", LOG_DEBUG)

	expire = time.time()-(60*60*conf["main"]["crchours"])
	while conf["runtime"]["endtime"] == 0:
		if childname and not (conf["main"]["pid"] and os.path.exists(conf["main"]["pid"])): break
### DO SOMETHING
		if conf["main"]["crcsave"]:
			tmpmb = {};
## Keep messages seen in last 12 hours
			for crc in msgbase:
				if not (msgbase[crc]["seen"] < expire):
					tmpmb[crc] = msgbase[crc].copy()

			msgbase = tmpmb.copy()
			tmpmb.clear()

			if conf["runtime"]["offline"]:
				save_vars(msgbase, conf["main"]["crcfile"])
### / DO SOMETHING
		if childname != "CRC" or not conf["main"]["childs"]: return
## Loop every 10 minutes
		if conf["main"]["crcsave"]:
			time.sleep(600)
		else:
			time.sleep(5)
	debug("CRC thread quited", LOG_INFO)
	return
### /CHILD THREADS




##############################################################################
### Main Functions
def debug(args=None, level=LOG_DEBUG, id=None, trace=None, verb=None):
	if conf["runtime"]["nodebug"]: return
	show = conf["runtime"]["args"]["debug"]
	if conf["runtime"]["args"]["v"]:
		show += conf["runtime"]["args"]["v"]

	if(level > show): return
	try:
		if(trace): debug("Trace path: %s" % (show_framepath()), level)
		if(trace):
			locals = sys._getframe().f_back.f_locals
			del locals["self"]
			debug("\tLocals for %s: %s" % (sys._getframe().f_back.f_code.co_name, locals), LOG_DEBUG, id=id)
#			print "\tGlobals:",show_vars(sys._getframe().f_back.f_globals)
	except:
		pass
	if args:
		print "%2d" % (level),
		print "\t%s" % (args)
	sys.stdout.flush()
	return

# Show (trace)path of functions
def show_framepath(f = None):
	hidden_functions = ["show_framepath", "debug"]

	if not f: f=sys._getframe()
	name = f.f_code.co_name
	if f.f_back:
		v = show_framepath(f.f_back)
		if v:
			if name not in hidden_functions: return v+" -> "+name+"()"
			else: return v
	if name in ["<module>"]: return None
	return name+"()"

def main():
	global conf

	if conf["main"]["childs"]:
# No signal support while threaded
		thread.start_new_thread(Tconfig,("Configuration Loader",))
	else:
# If we run as stand-alone, we need signals for config reloading with SIGHUP
		Tconfig()
		signal(SIGHUP , Tconfig)	# 1
		signal(SIGINT , cleanquit)	# ^C
		signal(SIGBUS , cleanquit)	# 7
		signal(SIGTERM, cleanquit)	# 15

	wtime = 0
	maxwtime = 5
	while conf["runtime"]["conftime"] == 0 and wtime < maxwtime:
		sys.stdout.flush()
		time.sleep(1)
		wtime += 1
	if conf["runtime"]["conftime"] == 0:
		debug("Couldn't load configuration file in %d seconds." % (maxwtime), LOG_ALERT)
		sys.stdout.flush()
		return
# Main loop
	debug("Main loop", LOG_DEBUG)
#	while os.access(conf["main"]["pid"], os.R_OK):
#		time.sleep(1)
	Milter.factory = SpamMilter
	Milter.set_flags(ADDRCPT + DELRCPT + ADDHDRS + CHGHDRS + CHGBODY)

	debug("Spam Filter started", LOG_INFO)

	if not usedns: debug("WARNING! DNS module not loaded, DNS functions (like RBL) disabled!", LOG_ALERT)
##	if conf["main"]["childs"]:
#		thread.start_new_thread(Tlogger,("Logger",))
##		thread.start_new_thread(Tcrc,("CRC",))

	try:
		Milter.runmilter(conf["main"]["name"],conf["main"]["port"],300)
	except SystemExit:
		pass
	except:
		debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
	cleanquit()

def cleanquit(arg1 = None, arg2 = None):
	global conf

	endtime = "%.0f" % time.time()
	debug("runtime was %.0f seconds" % (int(endtime)-int(conf["runtime"]["starttime"])), LOG_INFO)

	sys.stdout.flush()
	rmpid(conf["main"]["pid"])
	os._exit(0)

if __name__ == "__main__":
# ./sspamm.py -c sspamm.conf sample_spam.var -d
# Namespace(conf=['sspamm.conf'], debug=7, pid=False, v=None, varfile='sample_spam.var')

	conf["runtime"]["starttime"] = "%.0f" % time.time()
	parser = argparse.ArgumentParser(description='Semi\'s Spam Milter.')
	parser.add_argument('--ver', '-V', help='show version', action='version', version='%s v%s' % (__prog__, __version__))
	parser.add_argument('--conf', '-c', help='configuration file location', action='store', nargs=1)
	parser.add_argument('--test', '-t', help='tests to run, like: helo,ipfromto', action='store', nargs=1, dest='tests')
	parser.add_argument('--showpid', '-sp', help='show location of pid file', action='store_true', dest='showpid')
	parser.add_argument('--showconf', '-sc', help='show configuration dump', action='store_true', dest='showconf')
	parser.add_argument('--showmail', '-sm', help='dump debug data after mail processing', action='store_true', dest='showmail')
	parser.add_argument('-v', help='increase verbosity', action='count')
	parser.add_argument('--debug', '-d', help='debug level', action='store', nargs='?', const='7', type=int)
	parser.add_argument('varfile', metavar='spamfile.var', help='.var file to load (for testing)', nargs='?', type=str)
	conf["runtime"]["args"]=vars(parser.parse_args())

	try:
		conf["runtime"]["hostname"] = gethostname()[0:gethostname().index('.')]
	except:
		conf["runtime"]["hostname"] = gethostname()

	conf["runtime"]["startdir"] = os.getcwd()
	conf["runtime"]["bindir"] = sys.argv[0][0:sys.argv[0].rfind("/")]
	if not os.path.exists(conf["runtime"]["bindir"]):
		conf["runtime"]["bindir"] = os.getcwd()

	try:
		locale.setlocale(locale.LC_CTYPE, 'en_US.UTF-8')
		os.nice(5)
	except:
		pass

	a=conf["runtime"]["args"]
	if not conf["runtime"]["args"]["debug"]: conf["runtime"]["args"]["debug"] = LOG_NOTICE
	Tconfig(silent=True)
# Create PID or quit
	if(not makepid(conf["main"]["pid"])): sys.exit(2)

# CRC
	if conf["main"]["crcsave"]:
		if os.path.exists(conf["main"]["crcfile"]):
			if os.access(conf["main"]["crcfile"], os.R_OK):
				debug("Loading CRC database", LOG_NOTICE)
				msgbase = load_vars(conf["main"]["crcfile"])
			else:
				debug("Error accessing CRC file %s" % (conf["main"]["crcfile"]), LOG_ERR)
				conf["main"]["crcsave"] = False
		else:
			try:
				msgbase = {}
				msgbase["0"] = msgtemplate.copy()
				save_vars(msgbase, conf["main"]["crcfile"])
			except OSError, (errno, strerror):
				if errno != 39: debug("%s" % sys.exc_value, LOG_ERR)
				conf["main"]["crcsave"] = False
			except:
				debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
				conf["main"]["crcsave"] = False

	if a["showpid"]:
 		print conf["main"]["pid"]
		sys.exit(0)
	if a["showconf"]:
		print show_vars(conf)
		sys.exit(0)

	if a["varfile"]:
		if not os.path.exists(a["varfile"]):
			print "File %s not found." % (a["varfile"])
			sys.exit(1)
		test(a["varfile"]).feed2milter()
		sys.exit(0)
	else:
		print "MAIN"
#		main()

sys.exit(0)
