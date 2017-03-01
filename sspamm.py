#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# Note, I will use d.m.yyyy format, that's 19 feb 2017 = 19.2.2017

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
import thread
import ConfigParser

from socket import gethostname

from signal import signal, SIGINT, SIGHUP, SIGBUS, SIGTERM
from traceback import print_exc

## LOG_EMERG               = 0             #  system is unusable
## LOG_ALERT               = 1             #  action must be taken immediately
## LOG_CRIT                = 2             #  critical conditions
## LOG_ERR                 = 3             #  error conditions
## LOG_WARNING             = 4             #  warning conditions
## LOG_NOTICE              = 5             #  normal but significant condition
## LOG_INFO                = 6             #  informational
## LOG_DEBUG               = 7             #  debug-level messages
from syslog import \
	LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, \
	LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG

## http://sourceforge.net/projects/pymilter
## Ubuntu: spf-milter-python or "apt-get -y install py-milter"
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
		"accept":		"Accept",
		"block":		"Reject",
		"samefromto":		"Flag",
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
		"accept":		[],
		"block":		[],
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
	"rrd":		{
		"ham":		0,
		"unsure":	0,
		"spam":		0,
	},
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
		tmp = {}
		for i in self.getlines(section,option,[]):
			i=re.sub("\t| ", "", i).split(":")
			if '' in i: i.remove('')
			if len(i) == 1: i.append("all")
			t.append((i[0].split(","), i[1].split(",")))

			for val in t[len(t)-1][0]:
### On filter/domains. If no rules are defined, add all. Also append rules if
### defined with + on domain(s). And remove from default rules if prefixed
### with ! or -.
				retests = t[len(t)-1][1]
				if '' in retests: retests.remove('')

				tests = []
				rules = 0

				if 'all' in retests:
					retests += conf["filter"]["defaulttests"]
					retests.remove('all')
				for test in retests:
					if test in tests: continue
					tests.append(test)
					if test[0] >= 'a' and test[0] <= 'z':
						rules += 1
				if rules == 0:
					tests += conf["filter"]["defaulttests"]
				if 'all' in tests: tests.remove('all')

				tmplist = list(tests)
				for test in list(tests):
					if test[0] in ["-", "!"]:
						if test[1:] in tmplist: tmplist.remove(test[1:])
						tmplist.remove(test)
					elif test[0] == "+":
						if test[1:] in tmplist: tmplist.remove(test[1:])
						tmplist.remove(test)
						tmplist.append(test[1:])
				tmp[i[0]] = tmplist

		return tmp

# Checked 22.2.2017, - Semi
	def getrules(self,section,option,default=None,warn=False):
		t = []
		tmp = {}
		for i in self.getlines(section,option,[]):
			i=re.sub("\t| ", "", i).split(":")
			if '' in i: i.remove('')
			if len(i) > 1:
				t.append((i[0].split(","), ":".join(i[1:]).split(",")))

			for domain in t[len(t)-1][0]:
				if not tmp.has_key(domain): tmp[domain] = {}
				for rule in t[len(t)-1][1]:
					r = rule.split('=')
					if len(r) > 2:
						test=r[0].lower()
						param="=".join(r[1:])
					elif len(r) == 2:
						test=r[0].lower()
						param=r[1]
					else:
						test="rules"
						param=r[0]

					if test == "rules":
						if not tmp[domain].has_key(test): tmp[domain][test] = []
						tmp[domain][test].append(param)
					else:
						tmp[domain][test] = param
		return tmp

##############################################################################
### Configuration
def maildef():
	return {
		"id": 0,
		"tmpfile": None,
		"from": [],
		"to": [],
		"header": {
			"Received": [],
		},
		"received": {
			1: {
				"ip": None,
				"dns": None,
				"helo": None,
			}
		},
		"rawsubject": None,
		"raw": '',
		"timer": {},
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
					if conf[s][o] and conf[s][o][0] not in ["/", "."]: conf[s][o] = "%s/%s" % (conf["main"]["sspammdir"], conf[s][o])
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
# Just reminder how to do stuff... We need to work this part.
##		testconf = []
##		for t in conf[s]: if dumbregtest(t): testconf.append(t)
##		conf[s][o] = testconf
##		t = re.sub("^", "^", re.sub("\?", ".", re.sub("\.", "\.", t)))
##		t = re.sub("$", "$", re.sub("\*", ".*", re.sub("\?", ".", re.sub("\.", "\.", t))))
				elif o in ["accept", "block", "ipfromto"]:
					if o == "accept":
#						print show_vars(conf[s][o])
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
		t = re.sub("%s", conf["main"]["sspammdir"], t)
	if conf["runtime"].has_key("confpath") and conf["runtime"]["confpath"]:
		t = re.sub("%c", conf["runtime"]["confpath"], t)
	return t


##############################################################################
### Variable tools (we save/load variables)
# Checked 19.2.2017, - Semi
def save_vars(var, fname, id=None):
	debug("save_vars(\"%s\")" % (fname), LOG_DEBUG, id=id)
	fp = open(fname, "w+b")
	if fp: fp.write(show_vars(var))
	fp.close()
	return

# Note: This should be confirmed by someone else
# Checked 19.2.2017, - Semi - NOTE!
def load_vars(fname, id=None):
	debug("load_vars(\"%s\")" % (fname), LOG_DEBUG, id=id)
	fp = open(fname, "r")
	is_raw = False
	raw = None
	do_skip = False
	line_cont = False
	do_show = False
	name = None
	buf = ""

	while 1:
		line = fp.readline()
		if line == "}" or len(line) < 1:
			buf += line
			break
		if len(line) > 1 and line[1] == "\"":
			name = line[2:line.rfind("\"")]
			do_skip = False
		elif do_skip and line[1:3] == "},":
			do_skip = False
			continue

		if do_skip or name in ["mime", "result", "smtpcmds", "tests", "note", "rules", "charset", "checksum", "timer", "todomain", "ipfromto", "action", "size", "type", "my"]:
			do_skip = True
			continue
		elif name in ["raw"] and is_raw == False:
			is_raw = True
			raw = line[9:]
			continue
		if is_raw:
			if line[-3:] == "',\n":
				line = line[:-3]
				is_raw = False
			raw += line
			continue

#
# Note: line_cont is used to detect 'multiline' values from .var file. This
# WILL get broken if line does end with , but quotes are not closed!  This
# is known bug, and we will address it later.
#
		if not do_skip:
			if line[-2:] not in [",\n", "{\n", "(\n", "[\n"]:
				line_cont = True
			else:
				line_cont = False
			if line_cont:
				line = line[:-1]+"\\n"
				pass
			buf += line
	fp.close()
	vars = eval(buf)
	if raw: vars["raw"] = raw
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

### Timeme
## Used for trace processing time, so we can find if there is things that takes too long to complete
def timeme(timer=0):
	if timer == 0: return time.time()
	timer = float(time.time())-float(timer)
	if timer < 0: timer = 0
	return float(timer)

### parse_addrs
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

### Reverse DNS query (IP -> PTR)
def reversedns(ip, id=None):
	global usedns
	debug("reversedns(\"%s\")" % (ip), LOG_DEBUG, id=id)

	if not usedns:
		debug("NO DNS Module loaded", LOG_INFO, id=mail["id"])
		return None
	a = ip.split('.')

	if a[0] == "127" or a[0] == "10" or (a[0] == "192" and a[1] == "168") or (a[0] == "169" and a[1] == "254") or (a[0] == "172" and a[1] == "16") or (a[0] == "172" and a[1] == "17"):
		debug("* reversedns(\"%s\") = Private network" % (ip), LOG_DEBUG, id=id)
		return None

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

##############################################################################
### Basic fileoperations (Usualy we don't need to care if it success or not)
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
		return ("Error", sys.exc_value)
		debug("Couldn't create %s: %s" % (conf["main"]["pid"], tmp[1]), LOG_CRIT)
		return False
	return True

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

		debug("mail from:%s" % (mailfrom), LOG_INFO, id=self.id)
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
		if conf["main"]["timeme"]: self.mail["timer"]["smtp_"+sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
		return CONTINUE

	def header(self,field,value):
		if not self.mail["timer"].has_key("smtp_header") and conf["main"]["timeme"]: self.mail["timer"]["smtp_header"] = timeme()
		debug("SpamMilter.header(%s, %s)" % (field,value), LOG_DEBUG, id=self.id)
		return CONTINUE

	def eoh(self):
		debug("SpamMilter.eoh()", LOG_DEBUG, id=self.id)
		if conf["main"]["timeme"] and self.mail["timer"].has_key("smtp_header"):
			self.mail["timer"]["smtp_headers"] = str("%.4f") % timeme(self.mail["timer"]["smtp_header"])
			del self.mail["timer"]["smtp_header"]
		return CONTINUE

	def body(self,chunk):
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.body() (chunk size: %d)" % len(chunk), LOG_DEBUG, id=self.id)
		if conf["main"]["timeme"]: self.mail["timer"]["smtp_"+sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
		return CONTINUE

	def eom(self):
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.eom()", LOG_DEBUG, id=self.id)
		if conf["main"]["timeme"]: self.mail["timer"]["smtp_"+sys._getframe().f_code.co_name] = str("%.4f") % timeme(timer)
		return CONTINUE

##############################################################################
###
### Class for "manual" testing
###
class test:
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
		self.mail = load_vars(file)

		# Open temp file and write raw message into it

## What should we do, if file does not have 'raw' entry? Is that possible?
		if self.mail.has_key("raw") and self.mail["raw"]:
			self.tmp = open("%s.tmp" % (file), "w+b")
			self.tmp.write(self.mail["raw"])
			self.tmp.close()

			# Reopen tmp file as read-only and move to end
			# Now we should have system like when online
			self.tmp = open("%s.tmp" % (file), "r")
			#self.tmp.seek(0,2)	# Seek to end-of-file
			self.tmp.seek(0)	# Seek to begining-of-file

	def feed2milter(self):
		print "feed2milter"
		m = SpamMilter()

		m.mail["id"] = self.mail["id"]
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
# .
		m.eom()
# Close
		m.close()
		if self.tmp:
			self.tmp.close()
			rm(self.tmp.name)

# Configuration file
#		print show_vars(conf)
# "Client" data, this is message to be filtered (should be used as 'read-only')
#		print show_vars(self.mail)
# Our data, after all hard work
		print show_vars(m.mail)

# OBSOLETE
#	def run(self):
#		self.feed2milter()
#		sys.exit(0)

##############################################################################
###
### CHILD THREADS
###
def Tconfig(childname=None, doverbose=None):
	global conf, conffile

	debug("Tconfig(%s, %s)" % (childname, doverbose), LOG_DEBUG)
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
			debug("Config file %s found." % conf["runtime"]["conffile"], LOG_NOTICE)
			if conf["runtime"]["conftime"] > 0:
				save_config(conf["runtime"]["conffile"])
			conf["runtime"]["conftime"] = os.stat(conf["runtime"]["conffile"])[8]
			conf["runtime"]["confpath"] = conf["runtime"]["conffile"][0:conf["runtime"]["conffile"].rfind("/")]
			if childname: debug("Configuration %s reloaded" % (conf["runtime"]["conffile"]), LOG_NOTICE)
			load_config(conf["runtime"]["conffile"])
#			if conf["runtime"]["offline"]:
#				if doverbose: conf["main"]["offline"] = doverbose
#				conf["main"]["verbose"] = conf["main"]["offline"]

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

##############################################################################
### Main Functions
def debug(args, level=LOG_DEBUG, id=None, trace=None, verb=None):
	print "%2d\t%s" % (level, args)
	sys.stdout.flush()
	return

def main():
	global conf

# Run child (thread) configuration
	Tconfig()
# Create PID or quit
	if(not makepid(conf["main"]["pid"])): sys.exit(2)

	if conf["main"]["childs"]:
# No signal support while threaded
		thread.start_new_thread(Tconfig,("Configuration Loader",))
	else:
# If we run as stand-alone, we need signals for config reloading with SIGHUP
		Tconfig()
		signal(SIGHUP , Tconfig)   # 1
		signal(SIGINT , cleanquit) # ^C
		signal(SIGBUS , cleanquit) # 7
		signal(SIGTERM, cleanquit) # 15

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
	elif sys.argv[1:][0] == "pid":
		Tconfig()
		print conf["main"]["pid"]
		sys.exit(0)
	elif sys.argv[1:][0] == "conf":
		Tconfig()
		print show_vars(conf)
		sys.exit(0)
	elif os.path.exists(sys.argv[1:][0]):
		test(sys.argv[1:][0]).feed2milter()
	else:
		print """We need help here?"""
		sys.exit(1)

sys.exit(0)
