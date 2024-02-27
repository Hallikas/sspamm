#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""Semi's SPAM Milter - Who would like to get trash on email? Not me.
"""

__author__ = "Sami-Pekka Hallikas <semi@hallikas.com>"
__email__ = "semi@hallikas.com"
__date__ = "18 Aug 2010"
__version__ = "3.0-devel"

import sys
import os
import time
import datetime
from dateutil.parser import *
from dateutil import tz
import locale
import ConfigParser
import re
import thread
import formatter, htmllib, urllib
UseSHA=0
try:
# For python > 2.4
	UseSHA=25
	import hashlib
	
except:
# For Python >= 2.4
	UseSHA=24
	import sha

from email import message_from_file, message_from_string
from email.Header import decode_header
from string import maketrans, letters, digits, punctuation, whitespace
from string import split, join
from signal import signal, SIGINT, SIGHUP, SIGBUS, SIGTERM
from socket import gethostname

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

## rpmforge repository:
try:
	import rrdtool
	userrd = True
except:
	userrd = False

## http://sourceforge.net/projects/pydns
try:
	import DNS
	from DNS import Base
	usedns = True
	DNS.defaults['server'].append('8.8.8.8')
	DNS.defaults['timeout'] = 5
except:
	usedns = False

## http://sourceforge.net/projects/pymilter
## Ubuntu: spf-milter-python
import Milter
from milter import \
	ACCEPT, CONTINUE, REJECT, DISCARD, TEMPFAIL, \
	ADDHDRS, CHGBODY, ADDRCPT, DELRCPT, CHGHDRS

try: from milter import QUARANTINE
except: pass



##############################################################################
###
### Global variables / Configuration
###

conffile = "sspamm.conf"

confdefaults = {
	"main": {
		"name":			"sspamm3",
		"childs":		False,
		"port":			"local:/tmp/sspamm3.sock",
		"sspammdir":		None,
		"pid":			"sspamm3.pid",
		"logfile":		"sspamm3.log",
		"rrdfile":		"sspamm3.rrd",
		"crcfile":		"sspamm3.crc",
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
	"bindir":	None,
	"starttime":	0,
	"endtime":	0,
	"conftime":	0,
	"logtime":	0,
	"conffile":	None,
	"offline":	False,
	"rrd":		{
		"ham":		0,
		"unsure":	0,
		"spam":		0,
	},
}

msgbase = {
	0: {
		'seen': 0,
		'block': 0,
		'pass': 0,
		'flag': 0,
	}
}
hostname = None
globaltmp = {}
loglines = []

##############################################################################
###
### Configuration
###
class MyParser(ConfigParser.ConfigParser):
	def getvalue(self,section,option,default=None,warn=False):
		value = default
		try:
			value = self.getboolean(section, option)
		except ConfigParser.NoOptionError, (err):
			if warn:
				debug(err, LOG_ERR)
			pass
		except:
			try:
				value = self.getint(section, option)
			except:
				err = "Warning: No value for %s: %s" % (section, option)
				if warn:
					debug(err, LOG_ERR)
				pass
			pass
		return value

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
			if warn:
				debug(err, LOG_ERR)
			pass
		except:
			err = "Warning: No lines for %s: %s" % (section, option)
			if warn:
				debug(err, LOG_ERR)
			return None
		return default

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
			if warn:
				debug(err, LOG_ERR)
			pass
		except:
			err = "Warning: No list for %s: %s" % (section, option)
			if warn:
				debug(err, LOG_ERR)
			return None
		return default


def config_read(cfgfile = conffile):
	global hostname

	tmpconf = conf.copy()
	cp = MyParser()
	if not os.access(cfgfile, os.R_OK):
		print("FATAL: Can't access %s." % (cfgfile))
		return
	cp.read(cfgfile)

	if not (cp.has_section("main")):
		print("FATAL: Main section is missing!")
		return

	try:
		conf["main"]["verbose"] = cp.getvalue("main", "verbose")
	except:
		pass

	for s in confdefaults.keys():
		if cp.has_section(s):
			for k in confdefaults[s].keys():
				try:
					if 0:
						pass
## Filter/domains and filter/rules are very special cases and needs some special parsing
					elif "%s/%s" % (s,k) in ["filter/domains"]:
						t = []

						for i in cp.getlines(s, k, []):
							i=re.sub("\t| ", "", i).split(":")
							if '' in i: i.remove('')
							if len(i) == 1: i.append("all")
							t.append((i[0].split(","), i[1].split(",")))
						tmpconf[s][k] = t

					elif "%s/%s" % (s,k) in ["filter/rules"]:
						t = []

						for i in cp.getlines(s, k, []):
							i=re.sub("\t| ", "", i).split(":")
							if '' in i: i.remove('')
							if len(i) > 1:
								t.append((i[0].split(","), ":".join(i[1:]).split(",")))
						tmpconf[s][k] = t
					elif "%s/%s" % (s,k) in [ "filter/defaulttests", "settings/ipservers" ]:
						tmpconf[s][k] = cp.getlist(s, k)
					elif "%s/%s" % (s,k) in [ "main/verbose", "main/offline", "main/crchours", "settings/maxbodysize" ]:
						tmpconf[s][k] = cp.getint(s, k)
					elif "%s/%s" % (s,k) in [ "main/pid", "main/sspammdir", "main/tmpdir", "main/logfile", "main/savedir", "main/rrdfile", "main/crcfile" ]:
						tmpconf[s][k] = re.sub("%h", hostname, cp.get(s, k))
					elif "%s/%s" % (s,k) in [ "main/name", "main/port"]:
						tmpconf[s][k] = cp.get(s, k)
					elif s in [ "actions" ]:
						t = cp.get(s, k).lower()
						if t in [ "accept", "flag", "reject", "delete", "block", "discard" ]:
							tmpconf[s][k] = t
						else:
							debug("Warning %s/%s has invalid action type %s" % (s, k, t), LOG_ERR)
					elif "%s" % (s) in [ "rules" ]:
						testconf = []
						tmpconf[s][k] = cp.getlines(s, k, tmpconf[s][k])
						for t in tmpconf[s][k]:
							if dumbregtest(t): testconf.append(t)
						tmpconf[s][k] = testconf
					elif k in ["verbose", "enabled", "timeme", "watchmode", "childs", "crcsave", "nonspamonly", "confbackup"]:
						tmpconf[s][k] = cp.getvalue(s, k)
					elif type(tmpconf[s][k]) is int:
						debug("CONFIG INT %s / %s" % (s, k), LOG_ALERT)
						tmpconf[s][k] = cp.getint(s, k)
					elif type(tmpconf[s][k]) is list:
						debug("CONFIG LIST %s / %s" % (s, k), LOG_ALERT)
						tmpconf[s][k] = cp.getlist(s, k, tmpconf[s][k])
					else:
						debug("CONFIG UNKNOWN %s / %s" % (s, k), LOG_ALERT)
						tmpconf[s][k] = "** N/A **"
				except ConfigParser.NoOptionError:
					if "%s/%s" % (s,k) in [ "main/sspammdir", "main/timeme", "main/logfile", "main/savedir", "main/rrdfile", "main/crcfile"]:
						debug("Configuration value for %s/%s is not set." % (s, k), LOG_DEBUG)
						tmpconf[s][k] = None
					elif "%s/%s" % (s,k) in [ "main/name", "main/pid", "main/port", "main/verbose", "main/tmpdir" ]:
						debug("MISSING %s/%s, USING DEFAULTS" % (s, k), LOG_NOTICE)
						tmpconf[s][k] = confdefaults[s][k]
					elif "%s" % (s) in [ "actions" ]:
						debug("MISSING %s/%s" % (s, k), LOG_ALERT)
						pass
					else:
						debug("%s" % err, LOG_ERR)
						print_exc(limit=None, file=sys.stderr)
#				if tmpconf[s][k] == "None":
#					tmpconf[s][k] = None
#				else:
#					# Write 'our special regexp' (_ip and _dns) to real regexp
#					# Notice, even SPACE is rule separator!
#					if "%s" % (s) in [ "accept", "block", "ipfromto" ]:
#						testconf = []
#						for t in tmpconf[s]:
#							if dumbregtest(t): testconf.append(t)
#						tmpconf[s][k] = testconf
#					elif "%s/%s" % (s,k) in [ "connect/allow_ip", "connect/allow_dns", "connect/block_ip", "connect/block_dns", "rbl/skip_ip", "rbl/skip_dns", "dyndns/skip_ip", "dyndns/skip_dns" ]:
#						testconf = []
#						for t in tmpconf[s][k]:
#							if "%s/%s" % (s,k) in [] or ("%s/%s" % (s,k))[-3:] == "_ip":
#								t = re.sub("^", "^", re.sub("\?", ".", re.sub("\.", "\.", t)))
#							elif "%s/%s" % (s,k) in ["dyndns/rules"] or ("%s/%s" % (s,k))[-4:] == "_dns":
#								t = re.sub("$", "$", re.sub("\*", ".*", re.sub("\?", ".", re.sub("\.", "\.", t))))
#							if dumbregtest(t): testconf.append(t)
#						tmpconf[s][k] = testconf
		else:
			if s == "filter":
				debug("FATAL: Filter section is missing!", LOG_ERR)
				return
			if s != "runtime":
				debug("Section %s not found" % s, LOG_ERR)
				del tmpconf[s]

### Now config is fully loaded, do some special parsing.
## On filter/domains. If no rules are defined, add all. Also append rules if
## defined with + on domain(s). And remove from default rules if prefixed
## with ! or -.
	tmp = []
	for val in tmpconf["filter"]["domains"]:
		retests = val[1]
		if 'all' in val[1]:
			retests += tmpconf["filter"]["defaulttests"]
			retests.remove('all')
		else:
			retests = val[1]
		if '' in retests: retests.remove('')

		tests = []
		rules = 0
		action = {}
		for test in retests:
			if test in tests: continue
			tests.append(test)
			if test[0] >= 'a' and test[0] <= 'z':
				rules += 1
		if rules == 0:
			tests += tmpconf["filter"]["defaulttests"]
		if 'all' in tests: tests.remove('all')
		t = list(tests)
		for test in tests:
			if test[0] == "-" or test[0] == "!":
				if test[1:] in t: t.remove(test[1:])
				t.remove(test)
			if test[0] == "+":
				if test[1:] in t: t.remove(test[1:])
				t.remove(test)
				t.append(test[1:])
			
		tmp.append((val[0], t))
	tmpconf["filter"]["domains"] = tmp

	tmp = {}
	for val in tmpconf["filter"]["rules"]:
		for domain in val[0]:
			if not tmp.has_key(domain): tmp[domain] = {}
			for rule in val[1]:
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
	tmpconf["filter"]["rules"] = tmp

	return tmpconf

def config_load(file):
	global conf

	try:
		conf = config_read(file);
	except:
		debug("CONFIG LOAD ERROR. %s: %s" % (sys.exc_type, sys.exc_value), LOG_CRIT)
		print_exc(limit=None, file=sys.stderr)

def config_save(file):
	global conf

	try:
		fp = open("%s.bak" % (file), "w+b")
		tmpconf = conf.copy()
		del tmpconf["runtime"]
		fp.write(show_vars(tmpconf))
		fp.close()
	except:
		pass

##############################################################################
###
### Basic fileoperations (Usualy we don't need to care if it success or not)
###
def rm(file, id=None):
	debug("rm(\"%s\")" % (file), LOG_DEBUG, id=id)
	try:
		if os.path.exists(file): os.remove(file)
	except:
		pass
	return

def rmdir(path, id=None):
	debug("rmdir(\"%s\")" % (path), LOG_DEBUG, id=id)
	try:
		os.rmdir(path)
	except OSError, (errno, strerror):
		if errno != 39: debug("%s" % sys.exc_value, LOG_ERR)
	except:
		debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
	return

def mkdir(path, id=None):
	debug("mkdir(\"%s\")" % (path), LOG_DEBUG, id=id)
	try:
		os.makedirs(path, 0770)
	except OSError, (errno, strerror):
		if errno != 17: debug("%s" % sys.exc_value, LOG_ERR)
	except:
		debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
	return

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

##############################################################################
###
### Debug
###
def debug(args, level=LOG_DEBUG, id=None, trace=None):
	if conf["main"]["verbose"] >= 6: return
	datetime = ""
	msg = ""
	datetime = time.strftime('%Y%m%d %H:%M:%S')+" "+str(level)+" "
	if id:
		msg += "(%08d) " % (int(id))
	else:
		msg += "%8s " % ("")
	msg = str(msg) + str(args)
	msg = datetime + msg
	if level <= LOG_ERR:
		print(msg)
	elif level <= LOG_NOTICE and conf["main"]["verbose"] > 0:
		print(msg)
	elif level <= LOG_INFO and conf["main"]["verbose"] > 1:
		print(msg)
	elif conf["main"]["verbose"] > 2:
		print(msg)
	if trace:
		print_exc(limit=None, file=sys.stderr)
	sys.stdout.flush()
	return

def save_vars(var, fname, id=None):
	debug("save_vars(\"%s\")" % (fname), LOG_DEBUG, id=id)
	fp = open(fname, "w+b")
	if fp: fp.write(show_vars(var))
	fp.close()
	return

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

def show(string, comment=None):
	if comment: print("/* *** <%s> ******" % (comment))
	print(show_vars(string))
	if comment: print("***** </%s> *** */" % (comment))
	return

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
## Used for trace used time of processing, so one can find how long does
## each part of processing take.
def timeme(timer=0, noshow=None, id=None, title="Timer"):
	if timer == 0: return time.time()
	timer = float(time.time())-float(timer)
	if timer < 0: timer = 0
#	if not noshow: debug("\t%s: %.4f" % (title, timer), LOG_DEBUG, id=id)
	return float(timer)

### Oneliner
def oneliner(value, id=None):
#	debug("*oneliner(\"%s\")" % (value[0:160]), LOG_DEBUG, id=id)
	return re.sub(" + ", " ", re.sub("[\r\n]", "", re.sub("[\t]", " ", value)))
#
#2del# def oneliner(value, id=None, noshow=None):
#2del# 	if not noshow:
#2del# 		dots=""
#2del# 		if len(value) > 60: dots="..."
#2del# 		debug("*oneliner(\"%s%s\")" % (re.sub("\n", " ", value[0:60]), dots), LOG_DEBUG, id=id)
#2del# 	return re.sub(" + ", " ", re.sub("[\r\n\t]", " ", value))

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

def html_strip(htmlstr, id=None):
	if conf["main"]["timeme"] is True: timer = timeme()
	debug("*html_strip()", LOG_DEBUG, id=id)
	try:
		nohtml=HTMLStripper()
		htmlstr = re.sub("<font (color=.*? )?size=(\")?1(\")?>.*?</font>\n", "", re.sub("\\\\'", "\'", re.sub('\\\\"', '\"', htmlstr)))
		nohtml.feed(htmlstr)
		nohtml.close()
	except:
		if conf["main"]["timeme"] is True: timer = timeme()
		return(htmlstr, [])
#	if conf["main"]["timeme"] is True: mail["timer"]["html_strip"] = str("%.4f") % timeme(timer, id=id)
	return (re.sub("\(image\)", "", re.sub("\xa0", "", nohtml.gettext())), nohtml.anchorlist)

###
### Strip unprintable
###
def stripUnprintable(input_string, id=None):
#	debug("stripUnprintable()", LOG_DEBUG, id=id)
	try: filterUnprintable = stripUnprintable.filter
	except AttributeError: # only the first time it is called
		allchars = maketrans('','')
		delchars = allchars.translate(allchars, letters+digits+punctuation+whitespace)
		filterUnprintable = stripUnprintable.filter = lambda input: input.translate(allchars, delchars)
	return filterUnprintable(input_string)

###
### Unique keys
###
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

###
### Mime Part
###
def mimepart(part, lvl=0, param=None, id=None):
	if lvl == 0:
		debug("*mimepart()", LOG_DEBUG, id=id)
		if conf["main"]["timeme"] is True: timer = timeme()
	if not part.is_multipart() and part.get_content_type() != None:
		text = None
		if part.get_content_maintype() == "text":
			if part.get_content_subtype() == "plain" or part.get_content_subtype() == "html":
				text = part.get_payload(decode=True)
			else:
				if part.get_content_subtype() == "rfc822-headers":
					return
				debug("Unknown content type text/%s" % part.get_content_subtype(), LOG_DEBUG, id=id)
				return
				#text = part.get_payload(decode=True)
		if lvl>0:
			if text:
				return (part.get_content_maintype(), part.get_content_subtype(), "", param, text.strip())
			else:
				return (part.get_content_maintype(), part.get_content_subtype(), "", param, "")
		else:
			if text:
				return {0: (part.get_content_maintype(), part.get_content_subtype(), "", param, text.strip())}
			else:
				return {0: (part.get_content_maintype(), part.get_content_subtype(), "", param, "")}
		# Nothing to return
		return
	tree = {}
	sublvl=0
	tab="  "
	lvl+=1

	debug("\t%d.%d%s%s" % (lvl,sublvl,tab*lvl,part.get_content_type()), LOG_DEBUG, id=id)
	#tree[lvl*10+sublvl] = (part.get_content_type())
	if not part.get_payload():
		return tree
	for p in part.get_payload():
		ret = None
		if type(p) is str:
			if lvl > 1:
				return (part.get_content_maintype(), part.get_content_subtype(), "", param, part.get_payload().strip())
			return {10: (part.get_content_maintype(), part.get_content_subtype(), "", param, part.get_payload().strip())}
		if p.is_multipart():
			if p.get_param("x-spam-type") == "original":
				param="spam"
				tree = {}
			ret=mimepart(p, lvl, param, id=id)
			if ret:
				for r in ret:
					tree[r] = ret[r]
				continue
		else:
			sublvl += 1
			if p.get_param("x-spam-type") == "original":
				debug("\t%d.%d%s%s ( = original spam)" % (lvl,sublvl,tab*lvl,p.get_content_type()), LOG_DEBUG, id=id)
				msg=message_from_string(p.get_payload(decode=True))
				ret=mimepart(msg, lvl, param="spam", id=id)
			else:
				ret = mimepart(p, lvl, param, id=id)
		if ret:
			debug("\t%d.%d%s%s" % (lvl,sublvl,tab*lvl,p.get_content_type()), LOG_DEBUG, id=id)
			
			if p.get_param("x-spam-type"):
				tree = {}
			if type(ret) in [tuple]:
				tree[lvl*10+sublvl] = ret
			else:
				return ret
#	if lvl == 0 and conf["main"]["timeme"] is True: mail["timer"]["mimepart"] = str("%.4f") % timeme(timer)
	return tree


### dumbregtest
## Test regexp rules for stupid mistakes like || which would match EVERYTHING.
## If this test matches, rule should not be used!
def dumbregtest(regrule):
	try:
		test = re.search(regrule, "The quick brown fox jumps over the lazy dog.\n\t1234567890@${[]}!#&/()=*+-_,;:", re.IGNORECASE+re.MULTILINE)
		if test:
			debug("regexp error: Matched too easily: %s" % (regrule), LOG_ERR)
			return False
	except:
		return False
	return regrule

### Is Listed
## Test string and regexp for match
def is_listed(where,what,flags=re.IGNORECASE+re.MULTILINE,id=None,noshow=None,norecursive=False):
	if not noshow: noshow = True
	if conf["main"]["verbose"] == 5: noshow=False
	if what == None or where == None or len(what) < 1 or len(where) < 1: return
	if type(where) is str: where = [where]
	if type(what) is str: what = [what]

	if type(what) is dict:
		for a in what:
			tmp = is_listed(where,a,flags=flags,id=id,noshow=noshow)
			if tmp: return what[a]
	elif type(what[0]) is tuple:
		for a in what:
			tmp = is_listed(where,a[0],flags=flags,id=id,noshow=noshow)
			if tmp: return a[1]
	else:
		if not noshow: debug("\t -> is_listed()" % (where), LOG_DEBUG, id=id)
		for haystack in where:
			if not noshow: debug("\twhere = %s" % (where), LOG_DEBUG, id=id)
			for needle in what:
				if not noshow: debug("\t\t%s" % (needle), LOG_DEBUG, id=id)
				if id and globaltmp and globaltmp.has_key(id): globaltmp[id] += 1
				try:
					tmp = re.search("%s" % (needle), haystack, flags)
				except:
					debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
					debug("FAILED: is_listed(%s, %s)" % (haystack, needle), LOG_ERR, id=id)
					pass
				if tmp:
					if not noshow: debug("\t\t*is_listed - Matched", LOG_DEBUG, id=id)
#					if not noshow: debug("\t\t\tFrom: %s" % (haystack), LOG_DEBUG, id=id)
					if not noshow: debug("\t\t\tRegExp: %s" % (needle), LOG_DEBUG, id=id)
#					if not noshow: debug("\t\t\tMatch as: %s" % tmp.group(), LOG_DEBUG, id=id)
					tmpmatch = tmp.group()
## Should not be used, because it splits also (earth|moon) tests to two
## different tests, which raises error.
#				if not norecursive: is_listed(tmp.group(), needle.split('|'),noshow=True,norecursive=True)
					tmp = re.search("^\(\?#.*?\)", needle)
					if tmp: return (tmp.group()[3:-1], tmpmatch)
					return (True, tmpmatch)
	return None

### is filtered
def is_filtered(mail):
	if conf["main"]["timeme"] is True: timer = timeme()
	debug("is_filtered(%s)" % (mail["to"][0]), LOG_DEBUG, id=mail["id"])
	found = False
	try:
		mail["todomain"] = mail["to"][0].split("@")[1]
		found = is_listed(mail["todomain"], conf["filter"]["domains"], id=mail["id"])
		if found: debug("\tFound: %s" % (found), LOG_INFO, id=mail["id"])
	except:
		debug("FAILED: is_filtered %s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR, id=mail["id"], trace=True)
		mail["failed"] = "is_filtered(\"%s\"[0].split(\"@\")[1])" % (mail["to"])
		if not conf["runtime"]["offline"]:
			save_vars(mail, "/tmp/%08d.var" % (mail["id"]), id=mail["id"]);
	if conf["main"]["timeme"] is True: mail["timer"]["is_filtered"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (found, mail)

### DomainRule
def domainrule(mail, key, default=None):
	if not mail["rules"]: return default
	try:
		if mail["rules"].has_key(key):
			return mail["rules"][key]
		if mail["rules"].has_key("rules"):
			if key in mail["rules"]["rules"]: return True
			if '!'+key in mail["rules"]["rules"]: return False
	except:
		debug("%s: %s (domainrule)" % (sys.exc_type, sys.exc_value), LOG_ERR)
	return default


### Makepid
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

### parse_addrs
## Get only address part of address string. Do lowercase and strip blanks.
## Also return all parsed addresses as array.
def parse_addrs(addr, id=None):
#	debug("*parse_addrs(\"%s\")" % (addr), LOG_DEBUG, id=id)
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
	debug("*reversedns(\"%s\")" % (ip), LOG_DEBUG, id=id)
	if not usedns:
		debug("NO DNS Module loaded", LOG_INFO, id=id)
		return None
	a = split(ip, '.')

	if a[0] == "127" or a[0] == "10" or (a[0] == "192" and a[1] == "168") or (a[0] == "169" and a[1] == "254") or (a[0] == "172" and a[1] == "16"):
		debug("*reversedns() = Private network", LOG_DEBUG, id=id)
		return None
		
	debug("**reversedns(get ptr)", LOG_DEBUG, id=id)
	try:
		ptr = None
		if DNS.defaults['server'] == []: DNS.DiscoverNameServers()
		a.reverse()
		b = join(a, '.')+'.in-addr.arpa'
		if DNS.DnsRequest(b, qtype = 'ptr').req().header['status'] == "NOERROR":
			ptr=DNS.DnsRequest(b, qtype = 'ptr').req().answers[0]['data']
	except:
## Reason for exception is usually timeout, ignore
		debug("DNS query problems. %s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
		pass

	debug("\tPTR reply: %s" % (ptr), LOG_DEBUG, id=id)
	return ptr

### Generate ip:from:to stings
def makeipfromto(mail):
	if conf["main"]["timeme"] is True: timer = timeme()
	debug("*makeipfromto()", LOG_DEBUG, id=mail["id"])

#	if mail.has_key("ipfromto"): return
	tmp_fromto = {}

	for to in mail["to"]:
		tmp_fromto[to] = []
		for rec in mail["received"]:
			for to in mail["to"]:
				tmp = "%s:%s" % (mail["received"][rec]["ip"],mail["from"][0])
				if mail["received"][rec].has_key("dns"):
					tmp = "%s:%s" % (mail["received"][rec]["dns"],mail["from"][0])
					if tmp not in tmp_fromto[to]:
						debug("\t\tAppend %s" % (tmp), LOG_DEBUG, id=mail["id"])
						tmp_fromto[to].append(tmp)
				if tmp not in tmp_fromto[to]:
					debug("\t\tAppend %s" % (tmp), LOG_DEBUG, id=mail["id"])
					tmp_fromto[to].append(tmp)

	mail["ipfromto"] = tmp_fromto
	return 

### Fix received lines, remove hidden, etc.
def fix_received(mail):
	toremove = []
	debug("Fix received lines", LOG_DEBUG, id=mail["id"])
	for r in mail["received"]:
		debug("Received from %s" % (mail["received"][r]), LOG_INFO, id=mail["id"])

		# Now we have received lines, make readable and remove stupid entries
		if mail["received"][r].has_key("by"):
			del mail["received"][r]["by"]
		for f in mail["received"][r].keys():
			if mail["received"][r][f] == None:
				del mail["received"][r][f]

		if not mail["received"][r].has_key("ip"):
			toremove.append(r)
			continue
		
		debug("\tIs hidden?", LOG_DEBUG, id=mail["id"])
#		if is_listed(mail["received"][r].get("dns"), "^localhost", id=mail["id"]) or is_listed(mail["received"][r].get("ip"), "^127\.0\.0\.1", id=mail["id"]):
		if is_listed(mail["received"][r].get("ip"), "^127\.0\.0\.1", id=mail["id"]):
			toremove.append(r)
			continue
		elif is_listed(mail["received"][r].get("dns"), conf["rules"]["hide"], id=mail["id"]):
			toremove.append(r)
			continue
		elif is_listed(mail["received"][r].get("ip"), conf["rules"]["hide"], id=mail["id"]):
			toremove.append(r)
			continue

		try:
			if mail["received"][r].has_key("dns"):
				debug("\tIs DNS entry ok?", LOG_DEBUG, id=mail["id"])
				if mail["received"][r]["dns"][0] == "[" or is_listed(mail["received"][r]["dns"], ["^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"], id=mail["id"]):
					del mail["received"][r]["dns"]
				elif mail["received"][r].has_key("helo") and mail["received"][r]["dns"] == mail["received"][r]["helo"]:
					del mail["received"][r]["helo"]

			if mail["received"][r].has_key("helo"):
				debug("\tIs hello ok?", LOG_DEBUG, id=mail["id"])
				if mail["received"][r]["helo"][0] == "[":
					mail["received"][r]["helo"] = mail["received"][r]["helo"][1:-1]
				if is_listed(mail["received"][r]["helo"], ["^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"], id=mail["id"]):
					if mail["received"][r]["helo"] == mail["received"][r]["ip"]:
						del mail["received"][r]["helo"]
					elif is_listed(mail["received"][r]["helo"], ["^127\.", "^192\.168\.", "^10\."], id=mail["id"]):
						del mail["received"][r]["helo"]
		except:
			debug("%s: %s (eoh -> received fix)" % (sys.exc_type, sys.exc_value), LOG_ERR, id=mail["id"], trace=False)
			if not conf["runtime"]["offline"]:
# SEMI: This is so stupid, but save_vars says that 'self.mail' is not global
				try:
					if mail: save_vars(mail, "/tmp/%08d.var" % (mail["id"]), id=mail["id"]);
				except:
					debug("Exception in 'Is DNS entry ok' or 'Is hello ok'", LOG_ERR, id=mail["id"], trace=False)
					pass

	bck = mail["received"][1]
	tmp = mail["received"].copy()
	mail["received"].clear()
	seen = []
	i = 0
	for r in tmp:
		if r not in toremove:
			i += 1
			try:
				if i > 1:
					if mail["received"][i-1]["ip"] == tmp[r]["ip"]: continue
			except:
				pass
			if tmp[r]["ip"] not in seen:
				seen.append(tmp[r]["ip"])
				mail["received"][i] = tmp[r]
	if len(mail["received"]) == 0: mail["received"][1] = bck
	debug("Received lines fixed, %d entries removed, %s left." % (len(toremove), len(tmp)-len(toremove)), LOG_DEBUG, id=mail["id"])
	return mail


##############################################################################
### Filter tests
def test_connect(mail):
	debug("*test_connect()", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	res = None
	mail["tests"]["connect"] = 1
	globaltmp[mail["id"]] = 0

	if mail["received"][1]["ip"] == "127.0.0.1" or mail["received"][1]["ip"] == mail["my"]["ip"]:
		debug("\tSender is local (me)", LOG_DEBUG, id=mail["id"])
		res = ("accept", "LOCAL")
	else:
		for rec in mail["received"]:
			if not res and mail["received"][rec].has_key("dns"):
				debug("\tConnect from %s (dns)" % (mail["received"][rec]["dns"]), LOG_INFO, id=mail["id"])
				res = is_listed(mail["received"][rec]["dns"], conf["rules"]["connect"], id=mail["id"])
			if not res:
				debug("\tConnect from %s" % (mail["received"][rec]["ip"]), LOG_INFO, id=mail["id"])
				res = is_listed(mail["received"][rec]["ip"], conf["rules"]["connect"], id=mail["id"])
#                       if not res and mail["received"][rec].has_key("helo"):
#				debug("\tConnect from %s (helo)" % (mail["received"][rec]["helo"]), LOG_INFO, id=mail["id"])
#				res = is_listed(mail["received"][rec]["helo"], conf["rules"]["connect"], id=mail["id"])
			if res:
				break
## break for NOT to be RECURSIVE (Should it be? or not?)
			break

	if globaltmp and globaltmp.has_key(mail["id"]):
		debug("\tTests executed: %d" % (globaltmp[mail["id"]]), LOG_INFO, id=mail["id"])
		mail["tests"]["connect"] = globaltmp[mail["id"]]
		del globaltmp[mail["id"]]

	if res and res[0] == True:
		tmp = res[1]
		res = (conf["actions"]["connect"], tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["connect"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

def test_helo(mail):
	debug("*test_helo()", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	res = None
	mail["tests"]["helo"] = 0

	for rec in mail["received"]:
		if mail["received"][rec].has_key("helo"):
			helo = mail["received"][rec]["helo"]
			mail["tests"]["helo"] += 1
			debug("\thelo = %s" % (helo), LOG_INFO, id=mail["id"])

			if helo == mail["my"]["ip"]:
				debug("\t\tFound: %s = %s (my ip)" % (helo, mail["my"]["ip"]), LOG_DEBUG, id=mail["id"])
				res = (True, "My IP")
			elif mail["my"].has_key("dns") and helo == mail["my"]["dns"]:
				debug("\t\tFound: %s = my dns" % (helo), LOG_DEBUG, id=mail["id"])
				res = ("flag", "My DNS")
			elif mail.has_key("todomain") and helo == mail["todomain"]:
				debug("\t\ttest_helo: %s = todomain" % (helo), LOG_DEBUG, id=mail["id"])
				res = ("flag", "Rcpt Domain")
			else:
				res = is_listed(helo, conf["rules"]["helo"], id=mail["id"])
			if res:
				break

## NOT RECURSIVE (yet. Should it be?)
#		break

	if globaltmp and globaltmp.has_key(mail["id"]):
		del globaltmp[mail["id"]]

	if res and res[0] == True:
		tmp = res[1]
		res = (conf["actions"]["helo"], tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["helo"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

def test_accept(mail):
	if not conf.has_key("rules") or not conf["rules"].has_key("accept"):
		return(None, mail)
	makeipfromto(mail)
	debug("*test_accept()", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	mail["tests"]["accept"] = 0
	res = None
	globaltmp[mail["id"]] = 0

	for to in mail["ipfromto"]:
		for tmp in mail["ipfromto"][to]:
			res = is_listed(tmp+":"+to, conf["rules"]["accept"], id=mail["id"])
			if res:
				debug("\t\tMATCH, accept %s %s" % (res), LOG_INFO, id=mail["id"])
				if res[0] in ['break']: res = None
				break

	if globaltmp and globaltmp.has_key(mail["id"]):
		debug("\tTests executed: %d" % (globaltmp[mail["id"]]), LOG_INFO, id=mail["id"])
		mail["tests"]["accept"] = globaltmp[mail["id"]]
		del globaltmp[mail["id"]]

	if res and res[0] == True:
		tmp = res[1]
		res = (conf["actions"]["accept"], tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["accept"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

def test_block(mail):
	if not conf.has_key("rules") or not conf["rules"].has_key("block"):
		return(None, mail)
	makeipfromto(mail)
	debug("*test_block()", LOG_DEBUG, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	mail["tests"]["block"] = 0
	res = None
	globaltmp[mail["id"]] = 0

	if not (mail.has_key("result") and mail["result"].has_key("accept") and mail["result"]["accept"] and mail["result"]["accept"][0] in ['skip']):
		for to in mail["ipfromto"]:
			for tmp in mail["ipfromto"][to]:
				res = is_listed(tmp+":"+to, conf["rules"]["block"], id=mail["id"])
				if res:
					debug("\t\tMATCH, block %s %s" % (res), LOG_INFO, id=mail["id"])
					break

	if globaltmp and globaltmp.has_key(mail["id"]):
		debug("\tTests executed: %d" % (globaltmp[mail["id"]]), LOG_INFO, id=mail["id"])
		mail["tests"]["block"] = globaltmp[mail["id"]]
		del globaltmp[mail["id"]]

	if res and res[0] == True:
		tmp = res[1]
		res = (conf["actions"]["block"], tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["block"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

def test_ipfromto(mail):
	if not conf.has_key("rules") or not conf["rules"].has_key("ipfromto"):
		return(None, mail)
	makeipfromto(mail)
	debug("*test_ipfromto()", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	mail["tests"]["ipfromto"] = 0
	res = None
	globaltmp[mail["id"]] = 0

	for to in mail["ipfromto"]:
		for tmp in mail["ipfromto"][to]:
			res = is_listed(tmp+":"+to, conf["rules"]["ipfromto"], id=mail["id"])
			if res:
				debug("\t\tMATCH, ipfromto %s %s" % (res), LOG_INFO, id=mail["id"])
				if res[0] not in ['break', 'ignore', 'skip']:
					break
				continue

	if globaltmp and globaltmp.has_key(mail["id"]):
		debug("\tTests executed: %d" % (globaltmp[mail["id"]]), LOG_INFO, id=mail["id"])
		mail["tests"]["ipfromto"] = globaltmp[mail["id"]]
		del globaltmp[mail["id"]]

	if res and res[0] == True:
		tmp = res[1]
		res = (conf["actions"]["ipfromto"], tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["ipfromto"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

def test_samefromto(mail):
	debug("*test_samefromto()", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	res = None
	mail["tests"]["samefromto"] = 1

	h_from = []
	h_to = []

	m_from = mail["from"]
	m_to = mail["to"]

	if mail["header"].has_key("From"):
		a = re.search(r"<(.+?)>", mail["header"]["From"])
		if a:
			h_from.append(a.groups()[0])
	if mail["header"].has_key("To"):
		a = re.compile(r"<(.+?)>")
		for m in a.finditer(mail["header"]["To"]):
			h_to.append(m.group(1))

	debug("\t\tMail From:   %s" % (m_from), LOG_DEBUG, id=mail["id"])
	debug("\t\tMail To:     %s" % (m_to), LOG_DEBUG, id=mail["id"])
	debug("\t\tHeader From: %s" % (h_from), LOG_DEBUG, id=mail["id"])
	debug("\t\tHeader to:   %s" % (h_to), LOG_DEBUG, id=mail["id"])

#### OLD CODE BELOW
#	if len(mail["to"]) == 1 and mail["from"][0] == mail["to"][0]:
	if (m_from[0] != m_to[0]) and (m_to[0] in h_to) and (h_from[0] == m_to[0]) and (m_from[0] != h_from[0]):
		debug("\t\tMATCH, samefromto", LOG_INFO, id=mail["id"])
		debug("\t\t\tmail from != header from = header to = mail to", LOG_DEBUG, id=mail["id"])
		res = (True, "%s, MAILFROM %s" % (m_to[0], mail["from"][0]))

	if res and res[0] == True:
		tmp = res[1]
		res = (conf["actions"]["samefromto"], tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["samefromto"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

def test_headers(mail):
	debug("*test_headers()", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	res = None
	mail["tests"]["headers"] = 0
	globaltmp[mail["id"]] = 0

	for h in mail["header"]:
		# Duplicate headers
		if type(mail["header"][h]) is list:
			debug("\tDUPES %s" % (h), LOG_NOTICE, id=mail["id"])
			for h2 in mail["header"][h]:
				debug("\t%s: %s" % (h, h2), LOG_INFO, id=mail["id"])
				res = is_listed("%s: %s" % (h, h2), conf["rules"]["headers"], id=mail["id"])
				if res:
					break
			if res:
				break
		elif type(mail["header"][h]) is str:
			debug("\t%s: %s" % (h, mail["header"][h]), LOG_INFO, id=mail["id"])
			res = is_listed("%s: %s" % (h, mail["header"][h]), conf["rules"]["headers"], id=mail["id"])
			if res:
				break
		else:
			debug("\tSKIP HEADER %s - %s: %s" % (type(mail["header"][h]), h, mail["header"][h]), LOG_NOTICE, id=mail["id"])
			continue
		if res:
			debug("\t\tMATCH, headers %s %s" % (res), LOG_INFO, id=mail["id"])
			break

	if globaltmp and globaltmp.has_key(mail["id"]):
		debug("\tTests executed: %d" % (globaltmp[mail["id"]]), LOG_INFO, id=mail["id"])
		mail["tests"]["headers"] = globaltmp[mail["id"]]
		del globaltmp[mail["id"]]

	if res and res[0] == True:
		tmp = res[1]
		res = (conf["actions"]["headers"], tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["headers"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

def test_wordscan(mail):
	debug("*test_wordscan()", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	res = None

	if mail["size"] > conf["settings"]["maxbodysize"]*1024:
		return (res, mail)
	mail["tests"]["wordscan"] = 0
	globaltmp[mail["id"]] = 0

	part = "Subject"
	debug("\tScanning %s: %s" % (part, mail["subject"]), LOG_INFO, id=mail["id"])
	res = is_listed(mail["subject"], conf["rules"]["subject"], id=mail["id"])
#	if res:
#		debug("\t\tMATCH, wordscan/subject %s %s" % (res), LOG_INFO, id=mail["id"])

	if not res:
		res = is_listed(mail["subject"], conf["rules"]["blockwords"], id=mail["id"])
#		if res:
#			debug("\t\tMATCH, wordscan/subject (with blockwords) %s %s" % (res), LOG_INFO, id=mail["id"])

	if not res and mail.has_key("mime") and mail["mime"]:
		for a in mail["mime"]:
				tmp = re.sub("\r\n", "\n", mail["mime"][a][4])
				part = "%s%s" % (mail["mime"][a][1][0:1].upper(), mail["mime"][a][1][1:].lower())
				if mail["mime"][a][1] in ["html", "plain"]:
					if mail["mime"][a][1] in ["html"]:
						(tmp,links) = html_strip(tmp, id=mail["id"])
						if not res:
							debug("\tScanning %d: %s (links)" % (a, part), LOG_INFO, id=mail["id"])
							debug("\t\t%s" % (links), LOG_DEBUG, id=mail["id"])
							res = is_listed(links, conf["rules"]["links"], LOG_NOTICE, id=mail["id"])
						if not res:
							debug("\tScanning %d: %s (blockhtml)" % (a, part), LOG_INFO, id=mail["id"])
							res = is_listed(tmp, conf["rules"]["blockhtml"], id=mail["id"])
						if not res:
							debug("\tScanning %d: %s (blockhtml, oneliner)" % (a, part), LOG_INFO, id=mail["id"])
							res = is_listed(oneliner(tmp, id=mail["id"]), conf["rules"]["blockhtml"], id=mail["id"])
						if not res:
							debug("\tScanning %d: %s (blockwords)" % (a, part), LOG_INFO, id=mail["id"])
							res = is_listed(tmp, conf["rules"]["blockwords"], id=mail["id"])
					if not res and mail["mime"][a][1] in ["plain"]:
						if not res:
							debug("\tScanning %d: %s (oneliner)" % (a, part), LOG_INFO, id=mail["id"])
							res = is_listed(oneliner(tmp, id=mail["id"]), conf["rules"]["blockwords"], id=mail["id"])
						if not res:
							debug("\tScanning %d: %s (oneliner, stripped)" % (a, part), LOG_INFO, id=mail["id"])
							res = is_listed(re.sub(" + ", " ", re.sub("[^a-zA-Z0-9ÖÄÅöäå€\-:/,.%?!$@ \n]", " ", (oneliner(tmp, id=mail["id"])))), conf["rules"]["blockwords"], id=mail["id"])
					if not res:
						debug("\tScanning %d: %s" % (a, part), LOG_INFO, id=mail["id"])
						res = is_listed(tmp, conf["rules"]["blockwords"], id=mail["id"])
					if res:
						debug("\t\tMATCH, wordscan %s %s" % (res), LOG_INFO, id=mail["id"])
						break
				else:
					debug("\tSkip %d: %s" % (a, part), LOG_INFO, id=mail["id"])
				if res:
					debug("\t\tMATCH, wordscan N/A %s %s" % (res), LOG_INFO, id=mail["id"])
					break

	elif not res:
			tmp = re.sub("\r\n", "\n", mail["raw"])
			debug("\tScanning 'raw message'", LOG_INFO, id=mail["id"])
			scan = is_listed(tmp, conf["rules"]["blockwords"], id=mail["id"])
	else:
		debug("\t* Match found", LOG_DEBUG, id=mail["id"])
		debug("RES = %s %s" % (res), LOG_DEBUG, id=mail["id"])

	if globaltmp and globaltmp.has_key(mail["id"]):
		debug("\tTests executed: %d" % (globaltmp[mail["id"]]), LOG_INFO, id=mail["id"])
		mail["tests"]["wordscan"] = globaltmp[mail["id"]]
		del globaltmp[mail["id"]]

	if res and res[0] == True:
		tmp = res[1]
		res = (conf["actions"]["wordscan"], tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["wordscan"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

def test_dyndns(mail):
	debug("*test_dyndns()", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	res = None
	mail["tests"]["dyndns"] = 0
	globaltmp[mail["id"]] = 0

	for rec in mail["received"]:
		if not mail["received"][rec].has_key("skip") and mail["received"][rec].has_key("dns"):

			debug("\tDynDNS test for %d. %s" % (rec, mail["received"][rec]["dns"]), LOG_DEBUG, id=mail["id"])
			mail["received"][rec]["tested"] = True
			if not res: res = is_listed(mail["received"][rec]["ip"], conf["rules"]["dyndns"], id=mail["id"])
			if not res: res = is_listed(mail["received"][rec]["dns"], conf["rules"]["dyndns"], id=mail["id"])
			if res:
				debug("\t\tMATCH, dyndns - %s: %s" % (res[0], res[1]), LOG_INFO, id=mail["id"])
				if res[0] in ['ignore']:
					res = None
					continue
				if res[0] in ['skip','authmx','relay','break']:
					mail["received"][rec]["skip"] = res[0]
					break
				if res[0] == True:
					tmp = res[1]
					res = (True, "%s in %s" % (tmp, mail["received"][rec].get("dns")))
				break

	if globaltmp and globaltmp.has_key(mail["id"]):
		debug("\tTests executed: %d" % (globaltmp[mail["id"]]), LOG_INFO, id=mail["id"])
		mail["tests"]["dyndns"] = globaltmp[mail["id"]]
		del globaltmp[mail["id"]]

	if res and res[0] == True:
		tmp = res[1]
		res = (conf["actions"]["dyndns"], tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["dyndns"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

def test_rbl(mail):
	global usedns
	debug("*test_rbl()", LOG_INFO, id=mail["id"])
	if not usedns:
		debug("NO DNS Module loaded", LOG_INFO, id=mail["id"])
		return (None, mail)
	if conf["main"]["timeme"] is True: timer = timeme()
	res = None
	failed = 0
	mail["tests"]["rbl"] = 0
	globaltmp[mail["id"]] = 0

	dyntmp = []
	for d in conf["rules"]["dyndns"]:
		if d[0:3] == "(?#": dyntmp.append(d)

	DNS.defaults['timeout'] = 1
	if DNS.defaults['server'] == []: DNS.DiscoverNameServers()
		
	for rec in mail["received"]:
		if not (mail["received"][rec].has_key("skip") and  mail["received"][rec]["skip"] in ['skip']):
			debug("\tChecking %s" % (mail["received"][rec]["ip"]), LOG_DEBUG, id=mail["id"])
### NOTE, WHY? Why I do look all these addesses from dyndns? I do dyndns check for 2 times? WHY WHY?
			if not mail["received"][rec].has_key("seen"):
				res = None
				if not res: res = is_listed(mail["received"][rec]["ip"], dyntmp, id=mail["id"])
				if not res and mail["received"][rec].has_key("dns"): res = is_listed(mail["received"][rec]["dns"], dyntmp, id=mail["id"])
				if res and res[0] in ['skip', 'ignore']:
					mail["received"][rec]["skip"] = res
					continue
				if res and res[0] in ['break']:
					break
			res = None

			a = split(mail["received"][rec]["ip"], '.')
			a.reverse()
			for rbl in conf["settings"]["ipservers"]:
				if rbl[0:3] == "(?#":
					action = rbl[3:rbl.find(")")]
					rbl = rbl[rbl.find(")")+1:]
				else:
					action = conf["actions"]["rbl"]
				debug("\t\tFrom: %s (if match %s)" % (rbl, action), LOG_DEBUG, id=mail["id"])
				b=join(a, '.')+'.'+rbl
				try:
					globaltmp[mail["id"]] += 1
					q = DNS.DnsRequest(b, qtype = 'A').req()
					if q.header['status'] == "NOERROR":
						globaltmp[mail["id"]] += 1
						try:
							q = DNS.DnsRequest(b, qtype = 'TXT').req()
							if q.header['status'] == "NOERROR":
								res = (True, q.answers[0]['data'][0])
						except:
							pass
						if not res: res = (True, "BLACKLISTED from %s" % (rbl))
						break
				except:
## Reason for exception is usually timeout, ignore
#					debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
# If RBL was failed for some reason. And we have no results, wait for couple seconds and try again.
					if failed < 3:
						time.sleep(1)
					else:
						mail["note"] = "DNS Failure for black list testing."
						break
					failed += 1
					pass
## Break on first RBL match
				if res: break
			if res: break

	if globaltmp and globaltmp.has_key(mail["id"]):
		debug("\tTests executed: %d" % (globaltmp[mail["id"]]), LOG_INFO, id=mail["id"])
		mail["tests"]["rbl"] = globaltmp[mail["id"]]
		del globaltmp[mail["id"]]

	if res and res[0] == True:
		tmp = res[1]
		res = (action, tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["rbl"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

def test_charset(mail):
	debug("*test_charset()", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	res = None
	mail["tests"]["charset"] = 0
	globaltmp[mail["id"]] = 0

	if mail.has_key("charset"):
		for c in mail["charset"]:
			res = is_listed(c, conf["rules"]["charset"], id=mail["id"])
			if res and res[0] not in ['skip']:
				break

	if res and res[0] in ['skip']: res = None
	if globaltmp and globaltmp.has_key(mail["id"]):
		debug("\tTests executed: %d" % (globaltmp[mail["id"]]), LOG_INFO, id=mail["id"])
		mail["tests"]["charset"] = globaltmp[mail["id"]]
		del globaltmp[mail["id"]]

	if res and res[0] == True:
		tmp = res[1]
		res = (conf["actions"]["charset"], tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["charset"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

###
###
###
def test_date(mail):
	debug("*test_date()", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	res = None
	mail["tests"]["date"] = 1

	if mail["header"].has_key("Date"):
		envdate=parse(mail["header"]["Date"])
		nowdate=datetime.datetime.now(tz.UTC)

		if 604800 < (envdate-nowdate).total_seconds():
			res = 604800 < (envdate-nowdate).total_seconds()
	
	else:
		print("Where is my DATE header?")

	if res == True:
		res = ('delete', "Mail from future: %s" % (mail["header"]["Date"]))
	if conf["main"]["timeme"] is True: mail["timer"]["date"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

###
###
###
def test_crc(mail):
	if not conf["main"]["crcsave"]: return (None, mail)
	debug("*test_crc()", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	res = None
	mail["tests"]["crc"] = 0

	if mail.has_key("checksum") and msgbase.has_key(mail["checksum"]):
		if msgbase[mail["checksum"]]['block'] > 5:
			res = (conf["actions"]["crc"], ">5 block/%dh" % (conf["main"]["crchours"]))
		elif msgbase[mail["checksum"]]['block'] > 1:
			res = ('flag', ">1 block/%dh" % (conf["main"]["crchours"]))
		elif msgbase[mail["checksum"]]['flag'] > 5:
			res = (conf["actions"]["crc"], ">5 flag/%dh" % (conf["main"]["crchours"]))
		elif msgbase[mail["checksum"]]['flag'] > 1:
			res = ('flag', ">1 flag/%dh" % (conf["main"]["crchours"]))

	if res and res[0] == True:
		tmp = res[1]
		res = (conf["actions"]["crc"], tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["crc"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)

###
###
###
def test_bayesian(mail):
	debug("*test_bayesian()", LOG_INFO, id=mail["id"])
	if conf["main"]["timeme"] is True: timer = timeme()
	res = None
	mail["tests"]["bayesian"] = 0

	if res and res[0] == True:
		tmp = res[1]
		res = (conf["actions"]["bayesian"], tmp)
	if conf["main"]["timeme"] is True: mail["timer"]["bayesian"] = str("%.4f") % timeme(timer, id=mail["id"])
	return (res, mail)


##############################################################################
###
### SpamMilter Class 
###
class SpamMilter(Milter.Milter):
	def maildef(self):
		return {
			"smtpcmds": [ ],
			"timer": {},
			"my": {
				"ip": "",
				"dns": "",
			},
			"received": {
				1: {
					"ip": None,
					"dns": None,
					"helo": None,
				}
			},
			"from": [],
			"to": [],
			"todomain": "",
			"size": 0,
			"subject": "",
			"charset": "",
			"header": { },
			"tests": { },
			"type": "",
			"note": None,
		}

	def __init__(self):
## TODO
		self.id = Milter.uniqueID()
		debug("SpamMilter.__init__()", LOG_DEBUG, id=self.id)
		self.mail = self.maildef()
		self.mail["id"] = self.id
		self.tmpname = "%08d.tmp" % (self.id)
		try:
## Temp file in DISK
			if not os.path.exists(conf["main"]["tmpdir"]): mkdir(conf["main"]["tmpdir"])
			self.tmp = open("%s/%s" % (conf["main"]["tmpdir"], self.tmpname),"w+b")
		except IOError, (errno, strerror):
			debug("Temp file failure (%s: %s)" % (errno, strerror), LOG_DEBUG, id=self.id)
		except:
			debug("Temp file (%s) failure" % "%s/%s" % (conf["main"]["tmpdir"], self.tmpname), LOG_DEBUG, id=self.id)
		self.mail["tmpfile"]=self.tmpname

## This is runned for every SMTP Connection, and ONLY when Sendmail
## connects.
	def _cleanup(self):
		debug("SpamMilter._cleanup()", LOG_DEBUG, id=self.id)
# Update statistics
		if self.tmp:
			self.tmp.close()
			rm(self.tmp.name, id=self.id)
		if not self.mail:
			return
		if not self.mail["tests"]:
			del self.mail
			self.mail = None
			return

		if conf["main"]["crcsave"] and self.mail.has_key("checksum"):
			crc = self.mail["checksum"]
			if not msgbase.has_key(crc):
				msgbase[crc] = {
					'seen':		0,
					'block':	0,
					'pass':		0,
					'flag':		0,
				}
			msgbase[crc]['seen'] = int(time.time())
			if self.mail["action"][0] in ['reject','delete','discard','block']:
				msgbase[crc]['block'] += 1
			elif self.mail["action"][0] in ['flag','warn']:
				msgbase[crc]['flag'] += 1
			else:
				msgbase[crc]['pass'] += 1

		if conf["main"]["timeme"] and self.mail["timer"].has_key("timepass"): self.mail["timer"]["timepass"] = str("%.4f") % timeme(self.mail["timer"]["timepass"], id=self.id, title="TTimer")

###
### USED FOR DEBUG!
###
		if self.mail["size"] > 0:
			if not self.mail["header"].has_key("From"):
				if self.mail["header"].has_key("from"):
					self.mail["header"]["From"] = self.mail["header"]["from"]
				else:
					self.mail["header"]["From"] = ""
			if not self.mail["header"].has_key("To"):
				if self.mail["header"].has_key("to"):
					self.mail["header"]["To"] = self.mail["header"]["to"]
				else:
					self.mail["header"]["To"] = ""
			if conf["main"]["verbose"] == 6 or (conf["runtime"]["offline"] and conf["main"]["offline"] < 7):
				print
#				if conf["main"]["singleview"]:
#					print(""),
#				else:
				print("#############################################################################")
				print("Received:"),
				for rec in self.mail["received"]:
					print("\n\t"),
					if self.mail["received"][rec].has_key("dns"):
						print("%s" % (self.mail["received"][rec]["dns"])),
					print(" [%s]" % (self.mail["received"][rec]["ip"])),
					if self.mail["received"][rec].has_key("helo"):
						print(" (%s)" % (self.mail["received"][rec]["helo"])),
				print("""

ID:\t\t%s
Mail From:\t%s
From:\t\t%s
Rcpt To:\t%s
To:\t\t%s
Date:\t\t%s
Subject:\t%s
Size:\t\t%d
Checksum:\t%s""" % (
self.mail["id"],
self.mail["from"][0],
self.mail["header"]["From"],
self.mail["to"],
self.mail["header"]["To"],
self.mail["header"]["Date"],
self.mail["subject"][0:80],
self.mail["size"],
self.mail["checksum"]
))
				if conf["main"]["crcsave"]:
					print("\t\t", msgbase[self.mail["checksum"]])
				print
				tc = 0
				print("%s\t\t%s\t%s\t%s" % ("Test", "Time", "Tests", "Action and why"))
				print("-----------------------------------------------------------------------------")
				for t in self.mail["tests"]:
					if self.mail["timer"].has_key(t):
						print("%-15s %s\t" % (t, self.mail["timer"][t])),
					else:
						print("%-15s %s\t" % ("", "")),
					print("%5d\t" % (self.mail["tests"][t])),
					tc += self.mail["tests"][t]
					if self.mail["result"].has_key(t):
						if self.mail["result"][t] != None:
							print("%s\t" % (self.mail["result"][t][0])),
							print("%s" % (oneliner(self.mail["result"][t][1][0:80]))),
						else:
							print(""),
					print
				print("-----------------------------------------------------------------------------")
				print("%s\t\t%s\t" % ("TOTAL:", self.mail["timer"]["timepass"])),
				print("%5d\t" % (tc)),
				print("%s" % (self.mail["action"][0])),
				print
				print
			if conf["runtime"]["offline"] and len(loglines) > 0:
				print(loglines.pop(0))
			sys.stdout.flush()
###
### /USED FOR DEBUG!
###
		if not conf["main"]["childs"]: Tcrc()
		if conf["main"]["savedir"] and not conf["runtime"]["offline"]:
			if self.mail["action"][0] in ['delete', 'reject', 'block', 'discard']:
				if not conf["main"]["nonspamonly"]:
					save_vars(self.mail, "%s/%08d.var" % (conf["main"]["savedir"], self.mail["id"]));
			else:
				save_vars(self.mail, "%s/%08d.var" % (conf["main"]["savedir"], self.mail["id"]));
#		for a in ['raw']:
#			if self.mail.has_key(a): del self.mail[a]
#		for a in ['smtpcmds','tmpfile','rules','ipfromto','id']:
#			if self.mail.has_key(a): del self.mail[a]
#		for a in ['mime','header','type','from','charset','todomain','rawsubject','subject','my','id','size']:
#			if self.mail.has_key(a): del self.mail[a]
		del self.mail
		self.mail = None
		return

	def log(self,*msg):
		debug(msg, LOG_DEBUG, id=self.id)

	def abort(self):
		debug("SpamMilter.abort()", LOG_DEBUG, id=self.id)
		self._cleanup()
		return CONTINUE

	def close(self):
		debug("SpamMilter.close()", LOG_DEBUG, id=self.id)
		if self.mail: self.mail["smtpcmds"].append("close")
		self._cleanup()
		return CONTINUE

	def connect(self,host,family,hostaddr):
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.connect(%s, %s)" % (host,hostaddr), LOG_DEBUG, id=self.id)
# Crashes if IPV6 / SEMI
		if self.mail: self.mail["smtpcmds"].append("connect")
		self.mail["received"][1]["ip"] = hostaddr[0]
		self.mail["received"][1]["dns"] = reversedns(hostaddr[0], id=self.id)
		if conf["main"]["timeme"]: self.mail["timer"]["smtp_connect"] = str("%.4f") % timeme(timer, id=self.id, noshow=True)
		return CONTINUE

	def hello(self,host):
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.hello(%s)" % (host), LOG_DEBUG, id=self.id)
		if self.mail: self.mail["smtpcmds"].append("hello")
		self.mail["received"][1]["helo"] = host
		self.reuse = self.mail["received"][1]
		if conf["main"]["timeme"]: self.mail["timer"]["smtp_hello"] = str("%.4f") % timeme(timer, id=self.id, noshow=True)
		return CONTINUE

	def envfrom(self,mailfrom,*vars):
		if not self.mail or "eom" in self.mail["smtpcmds"]:
			self._cleanup()
			debug("Connection reused", LOG_DEBUG, id=self.id)
			self.__init__()
			self.mail["received"][1] = self.reuse
			self.mail["smtpcmds"].append("reused")

		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.envfrom(\"%s\", %s)" % (mailfrom,vars), LOG_DEBUG, id=self.id)
		debug("mail from:%s" % (mailfrom), LOG_INFO, id=self.id)
		if conf["main"]["timeme"]: self.mail["timer"]["timepass"] = timeme()
		if self.mail: self.mail["smtpcmds"].append("envfrom")

		if mailfrom == "<>":
			if self.mail["received"][1].has_key("dns"):
				mailfrom = "<MAILER-DAEMON@%s>" % (self.mail["received"][1]["dns"])
			else:
				mailfrom = "<MAILER-DAEMON@[%s]>" % (self.mail["received"][1]["ip"])
		self.mail["from"] = parse_addrs(mailfrom, id=self.id)

		if not conf["runtime"]["offline"]:
			self.mail["my"]["ip"] = self.getsymval('{if_addr}')
			self.mail["my"]["dns"] = self.getsymval('{if_name}')
			if self.getsymval('{auth_type}'):
				self.mail["smtp_auth"] = self.getsymval('{auth_authen}')

		if conf["main"]["timeme"]: self.mail["timer"]["smtp_envfrom"] = str("%.4f") % (timeme(timer, id=self.id, noshow=True))

		return CONTINUE

	def envrcpt(self,rcpt,*vars):
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.envrcpt(\"%s\")" % (rcpt), LOG_DEBUG, id=self.id)
		debug("rcpt to:%s" % (rcpt), LOG_INFO, id=self.id)
		if self.mail: self.mail["smtpcmds"].append("envrcpt")

		if rcpt.startswith('<MAILER-DAEMON@'): debug("?To MAILER-DAEMON ?", LOG_DEBUG, id=self.id)

		if len(self.mail["to"]) > 0 and rcpt not in self.mail["to"]:
			self.mail["to"].append(parse_addrs(rcpt, id=self.id)[0])
		else:
			self.mail["to"] = parse_addrs(rcpt, id=self.id)

		if conf["main"]["timeme"]:
			if self.mail["timer"].has_key("smtp_envrcpt"):
				self.mail["timer"]["smtp_envrcpt"] = str("%.4f") % (float(self.mail["timer"]["smtp_envrcpt"]) + timeme(timer, id=self.id, noshow=True))
			else:
				self.mail["timer"]["smtp_envrcpt"] = str("%.4f") % (timeme(timer, id=self.id, noshow=True))
		return CONTINUE

	def header(self,field,value):
		if conf["main"]["timeme"]: timer = timeme()
		if self.mail and "header" not in self.mail["smtpcmds"]: self.mail["smtpcmds"].append("header")
		debug("SpamMilter.header(%s, %s)" % (field,value), LOG_DEBUG, id=self.id)

		if self.tmp and len(self.mail["header"]) == 0:
			self.tmp.write("From %s %s\n" % (self.mail["from"][0], time.ctime()))
			self.mail["size"] = 0
			self.mail["subject"] = ""
		if self.tmp: self.tmp.write("%s: %s\n" % (field, value))

## Note, this is NOT endless loop, it is just used like switch-case
## statement. We break out when perferred line has been processed.
## Save header line as is, before prosessing

		while 1:
## Headers to drop ... just proof-of-concept
			lfield = field.lower()
			if lfield in [ "x-spambayes-classification", "x-spam-level" ]:
				break

			onelinerh = oneliner(value, id=self.id).strip()
			if self.mail["header"].has_key(field) and lfield not in [ "subject", "date" ]:
				if type(self.mail["header"][field]) is not list:
					tmp = self.mail["header"][field]
					del self.mail["header"][field]
					self.mail["header"][field] = [ tmp ]
				self.mail["header"][field].append(onelinerh)
			else:
				self.mail["header"][field] = onelinerh

			if lfield == "date":
				self.mail["header"]["Date"]=self.mail["header"][field][:]
			if lfield == "subject":
				self.mail["subject"] = self.mail["header"][field][:]
				break

			if lfield == "received":
				a = re.compile("(?:from ((?P<ip3>[\d\.]+)|(?P<helo>\S+)) (?:\(helo (?P<helo2>[\w\d\.]+?)\) )?((?:\(?(?:\w+@)?(?:\S+(?: )?)?)?(?:(?:\[)(?P<ip>[\d.]+?)(?:\](?:[: ].+?)?))\)? )?|(\((?P<ip2>[\d\.]+?)\) )?)(?:\(using .*?\))?by (?P<by>.+?)(?: \(.+?\))? (with|id) ").match(onelinerh.lower())
				if a == None:
					break
				reclen = len(self.mail["received"])+1

				self.mail["received"][reclen]=a.groupdict()
				if self.mail["received"][reclen]["ip"] == None and self.mail["received"][reclen]["ip3"] != None: self.mail["received"][reclen]["ip"] = self.mail["received"][reclen]["ip3"]
				del self.mail["received"][reclen]["ip3"]
				if self.mail["received"][reclen]["ip"] == None and self.mail["received"][reclen]["ip2"] != None: self.mail["received"][reclen]["ip"] = self.mail["received"][reclen]["ip2"]
				del self.mail["received"][reclen]["ip2"]
				if self.mail["received"][reclen]["ip"] == None:
					del self.mail["received"][reclen]
					break
				if self.mail["received"][reclen]["ip"] != "127.0.0.1":
					self.mail["received"][reclen]["dns"] = reversedns(self.mail["received"][reclen]["ip"])
				if self.mail["received"][reclen]["helo"] == None and self.mail["received"][reclen]["helo2"] != None: self.mail["received"][reclen]["helo"] = self.mail["received"][reclen]["helo2"]
				del self.mail["received"][reclen]["helo2"]

				break
			break

		if conf["main"]["timeme"]:
			if self.mail["timer"].has_key("smtp_header"):
				self.mail["timer"]["smtp_header"] = str("%.4f") % (float(self.mail["timer"]["smtp_header"]) + timeme(timer, id=self.id, noshow=True))
			else:
				self.mail["timer"]["smtp_header"] = str("%.4f") % (timeme(timer, id=self.id, noshow=True))
		return CONTINUE

	def eoh(self):
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.eoh()", LOG_DEBUG, id=self.id)
		if self.mail: self.mail["smtpcmds"].append("eoh")
## Received fix was here. Also it would be safe to do accept, block, ipfromto, dyndns, rbl, headers test here.
		if conf["main"]["timeme"]: self.mail["timer"]["smtp_eoh"] = str("%.4f") % (timeme(timer, id=self.id, noshow=True))
		return CONTINUE

	def body(self,chunk):
		global UseSHA
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.body() (chunk size: %d)" % len(chunk), LOG_DEBUG, id=self.id)

		if self.mail: self.mail["smtpcmds"].append("body")
		if self.tmp and self.mail["size"] == 0:
			self.tmp.write("\n")
# Make SHA checksum only for first chunk of message, maximum size of chunk
# seems to be 65535. So if first 64K bytes of message is same, so is
# checksum. But usually this is not needed.
# For python > 2.4
			if UseSHA > 24:
				self.mail["checksum"] = hashlib.sha1(chunk).hexdigest()
# For Python >= 2.4
			elif UseSHA > 0:
				self.mail["checksum"] = sha.new(chunk).hexdigest()

		self.mail["size"] += len(chunk)
		if self.tmp: self.tmp.write(chunk)

		if conf["main"]["timeme"]: self.mail["timer"]["smtp_body"] = str("%.4f") % (timeme(timer, id=self.id, noshow=True))
		return CONTINUE

	def eom(self):
		if conf["main"]["timeme"]: timer = timeme()
		debug("SpamMilter.eom()", LOG_DEBUG, id=self.id)
		if self.mail: self.mail["smtpcmds"].append("eom")

## Sample how filter can 'answer' mail messages
		if self.mail["to"][0][0:11] == "spamfilter@":
			debug("Test request from %s" % self.mail["from"][0], LOG_INFO, id=self.id)
			if not conf["runtime"]["offline"]:
				self.delrcpt(self.mail["to"][0])
				self.addrcpt(self.mail["from"][0])
				self.chgheader("MIME-Version", 1, "")
				self.chgheader("Reply-To", 0, "")
				self.chgheader("From", 0, "Spam Filter <abuse@%s>" % (self.mail["my"]["dns"]))
				self.chgheader("Content-Type", 1, "text/plain")
				self.chgheader("Subject", 1, "Test message from %s" % (self.mail["from"][0]))
				self.replacebody("""

Your test message was received

""")
				return Milter.ACCEPT

## Authenticated sender, accept without logging
		if self.mail.has_key("smtp_auth"):
			debug("\tskip, authenticated", LOG_DEBUG, id=self.id)
			return Milter.ACCEPT

## What if Domain (not) found from filtered list
		(tests, self.mail) = is_filtered(self.mail)

		if not tests:
			debug("\tskip, not filtered domain", LOG_DEBUG, id=self.id)
			return Milter.CONTINUE
		else:
			self.mail["rules"] = is_listed(self.mail["todomain"], conf["filter"]["rules"], id=self.id)

		if self.mail["size"] == 0 and self.mail["subject"] == "":
			self.mail["type"] = "empty"
			return Milter.DISCARD

		subchar = []
		self.mail["subject"] == "(none)"
		try:
			if self.tmp:
				self.tmp.seek(0)
				msg = message_from_file(self.tmp)
				(subj, subchar) = decode_header(msg["subject"])[0]
				self.mail["subject"] = oneliner(stripUnprintable(subj), id=self.id)
				self.mail["rawsubject"] = oneliner(stripUnprintable(msg["subject"]), id=self.id)
				self.mail["raw"] = """%s""" % msg
				self.mail["mime"] = mimepart(msg, id=self.id)
				charset = msg.get_charsets()
				charset.append(subchar)
				self.mail["charset"]=uniq(charset)
		except:
				debug("EOM Exception, REJECTED", LOG_ERR, id=self.id)
		try: self.setreply("421", "4.2.1", "Error while parsing MIME structre of message, try again.")
		except: pass
#			return Milter.REJECT
		debug("eom(): %s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR, id=self.id, trace=False)
		if self.tmp:
			self.tmp.close()
			mv(self.tmp.name, "/tmp/%s" % (self.tmpname))
			save_vars(self.mail, "/tmp/%s.var" % (self.tmpname), id=self.mail["id"]);
			debug("saved as /tmp/%s" % (self.tmpname), LOG_ERR, id=self.id, trace=False)
		return Milter.CONTINUE
# If message is aborted, there probably is not self. So
        
		if self.mail:
			fix_received(self.mail)
		else:
			reason = "Error while starting prosessing"
		try: self.setreply("451", "4.5.1", reason)
		except: pass
		debug("Milter.REJECT (451 4.5.1 - %s)" % (reason), LOG_DEBUG, id=self.mail["id"])
		return REJECT
##
## Now message is received and processed. Fun part begins now, testing.
##
		self.mail["result"] = {}
		self.mail["action"] = [ "pass" ]
		flags = []
		for test in tests:
			if test in ['disable']: continue
			try:
				(ret, self.mail) = eval("test_"+test)(self.mail)
				self.mail["result"][test] = ret

				if ret:
					debug("do test_%s = %s ..." % (test, ret[0]), LOG_DEBUG, id=self.id)
				if ret and ret[0].lower() in ['flag', 'warn']:
					flags.append("'%s: %s'" % (test, oneliner(ret[1])))
				if ret and ret[0].lower() in ['flag-', 'flag+']:
					flags.append("'%s: %s'" % (test, oneliner(ret[1])))
				if ret and ret[0].lower() not in ['authmx', 'skip', 'break']:
					self.mail["action"].insert(0, ret[0].lower())
				if ret and (ret[0][-1] in ['-']):
					debug("  flag with - ... keep testing", LOG_DEBUG, id=self.id)
					lastreason = ret[1]
				if ret and (ret[0].lower() in ['reject', 'delete', 'block', 'discard', 'accept', 'ignore'] or ret[0][-1] in ['+']):
					debug("  break match found %s %s" % (ret[0].lower(), ret[0][-1]), LOG_DEBUG, id=self.id)
					break
				continue
			except:
				debug("ERROR: test_%s failed" % (test), LOG_DEBUG)
				debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_DEBUG, id=self.id, trace=True)
				if conf["runtime"]["offline"]:
					save_vars(self.mail, "/tmp/%s.var" % (self.tmpname), id=self.mail["id"]);
			continue

		if conf["main"]["timeme"]: self.mail["timer"]["smtp_eom"] = str("%.4f") % (timeme(timer, id=self.id, noshow=True))

		if self.mail["action"]:
			debug("Actions %s" % (self.mail["action"]), LOG_DEBUG, id=self.mail["id"])
			reason = "Blocked by Sspamm Spam Filter"
			action = self.mail["action"][0]
			if action[-1] in ['+', '-']:
				action = action[0:-1]
			if action in ['skip']: action = 'pass'
			debug("Current Action: %s" % (action), LOG_DEBUG, id=self.mail["id"])

		if action in ['reject'] and not (domainrule(self.mail, 'watch', conf["main"]["watchmode"]) or domainrule(self.mail, 'flagall')):
			debug("Message will be rejected, don't make any header changes!", LOG_DEBUG, id=self.mail["id"])
		else:
			if conf["runtime"]["offline"]: debug("X-%s-ID: %s" % (conf["main"]["name"], self.mail["id"]), LOG_DEBUG, id=self.mail["id"])
			try: self.chgheader("X-%s-ID" % (conf["main"]["name"]), 1, self.mail["id"])
			except: pass

			if conf["runtime"]["offline"]: debug("X-%s-Scanned: %s" % (conf["main"]["name"], time.strftime('%d.%m.%Y %H:%M:%S')), LOG_DEBUG, id=self.mail["id"])
			try: self.chgheader("X-%s-Scanned" % (conf["main"]["name"]), 1, time.strftime('%d.%m.%Y %H:%M:%S'))
			except: pass

			if conf["runtime"]["offline"]: debug("X-%s-Tests: %s" % (conf["main"]["name"], ", ".join(self.mail["tests"])), LOG_DEBUG, id=self.mail["id"])
			try: self.chgheader("X-%s-Tests" % (conf["main"]["name"]), 1, ", ".join(self.mail["tests"]))
			except: pass

			if conf["runtime"]["offline"]: debug("X-%s-Action: %s" % (conf["main"]["name"], action), LOG_DEBUG, id=self.mail["id"])
			try: self.chgheader("X-%s-Action" % (conf["main"]["name"]), 1, action)
			except: pass

			if self.mail["note"]:
				if conf["runtime"]["offline"]: debug("X-%s-Note: %s" % (conf["main"]["name"], ", ".join(self.mail["note"])), LOG_DEBUG, id=self.mail["id"])
				try: self.chgheader("X-%s-Note" % (conf["main"]["name"]), 1, ", ".join(self.mail["note"]))
				except: pass

			if ret:
				if conf["runtime"]["offline"]: debug("X-%s-Reason: %s: %s" % (conf["main"]["name"], test, oneliner(ret[1])), LOG_DEBUG, id=self.mail["id"])
				try: self.chgheader("X-%s-Reason" % (conf["main"]["name"]), 1, "%s: %s" % (test, oneliner(ret[1])))
				except: pass

			if (flags and ret) and (flags[0] != "'%s: %s'" % (test, ret[1]) or len(flags) > 1):
				if conf["runtime"]["offline"]: debug("X-%s-Flags: %s" % (conf["main"]["name"], ", ".join(flags)), LOG_DEBUG, id=self.mail["id"])
				try: self.chgheader("X-%s-Flags" % (conf["main"]["name"]), 1, ", ".join(flags))
				except: pass

		debug("Current Action(2): %s" % (action), LOG_DEBUG, id=self.mail["id"])
		if action not in ['ignore']:
			for to in self.mail["to"]:
				log = "%s" % time.strftime('%Y%m%d %H:%M:%S')
				log += " (%s)" % (self.mail["id"])
				log += " %s" % (action)

				if domainrule(self.mail, 'watch', conf["main"]["watchmode"]): log += "W"
				if domainrule(self.mail, 'flagall'): log += "F"
				if ret and action not in ['pass']:
					log += " (%s: %s" % (test.lower(), ret[1][:80])
					if len(ret[1]) > 80:
						log += "..."
					log += ")"
				else:
					if flags:
						log += " (%s)" % flags[0][1:-1]
					else:
						log += " ()"

				log += " %d" % (int(self.mail["size"]))
				log += " %s" % (self.mail["received"][1]["ip"])
				if self.mail["received"][1].has_key("dns"):
					log += " (%s)" % (self.mail["received"][1]["dns"])
				else:
					log += " ()"
				log += " <%s> <%s> %s" % (self.mail["from"][0], to, self.mail["subject"])

				if self.mail["action"] and self.mail["action"][0] not in ['ignore']:
					loglines.append(oneliner(stripUnprintable(log)))

		if not conf["main"]["childs"]: Tlogger()

		if self.mail["action"]:
			if action in ['reject','delete','discard','block']:
				conf["runtime"]["rrd"]["spam"] += 1
			elif action in ['flag','warn']:
				conf["runtime"]["rrd"]["unsure"] += 1
			elif action not in ['ignore'] :
				conf["runtime"]["rrd"]["ham"] += 1

			if action in ['reject']:
				if not (domainrule(self.mail, 'watch', conf["main"]["watchmode"]) or domainrule(self.mail, 'flagall')):
					try: self.setreply("550", "5.7.1", reason)
					except: pass
					debug("Milter.REJECT (550 5.7.1 - %s)" % (reason), LOG_DEBUG, id=self.mail["id"])
					return REJECT

			elif action in ['delete','discard','block']:
				if not (domainrule(self.mail, 'watch', conf["main"]["watchmode"]) or domainrule(self.mail, 'flagall')):
					debug("Milter.DISCARD (%s)" % (reason), LOG_DEBUG, id=self.mail["id"])
					return DISCARD

			if not domainrule(self.mail, 'watch', conf["main"]["watchmode"]):
				if action in ['flag','warn'] or (domainrule(self.mail, 'flagall') and action in ['reject','delete','discard','block']):
					if not re.search("{SPAM}: ", self.mail["subject"], re.IGNORECASE):
						if conf["runtime"]["offline"]: debug("Subject: {SPAM}: %s" % (self.mail["subject"]), LOG_DEBUG, id=self.mail["id"])
						try: self.chgheader("Subject", 1, "{SPAM}: %s" % (self.mail["subject"]))
						except: pass
				if domainrule(self.mail, 'flagall'):
					self.mail["action"].insert(0, "%s in FLAG ALL MODE" % (self.mail["action"][0]))
			else:
				self.mail["action"].insert(0, "%s in WATCH MODE" % (self.mail["action"][0]))

			debug("Milter.ACCEPT", LOG_DEBUG, id=self.mail["id"])
			return ACCEPT
		debug("Milter.CONTINUE", LOG_DEBUG, id=self.mail["id"])
		return CONTINUE

### List of Milter commands:
##	def setreply(self,rcode,xcode=None,msg=None,*ml):
##	def addheader(self,field,value,idx=-1):
##	def chgheader(self,field,idx,value):
##	def addrcpt(self,rcpt,params=None):
##	def delrcpt(self,rcpt):
##	def replacebody(self,body):
##	def chgfrom(self,sender,params=None):
##	def quarantine(self,reason):
##	def progress(self):


##############################################################################
###
### CHILD THREADS
###
def Tconfig(childname=None):
	global conffile, conf, msgbase
	
	if not conf["runtime"]["offline"]:
		debug("Tconfig", LOG_DEBUG)
	if conf["runtime"]["conffile"] == None:
		files = [ ]
		if conffile[0] != "/":
			files.append("/data/%s" % conffile)
			files.append("%s/%s" % (conf["runtime"]["startdir"], conffile))
			files.append("%s/%s" % (conf["runtime"]["bindir"], conffile))
			files.append("/etc/sspamm/%s" % conffile)
			files.append("/etc/%s" % conffile)
			files.append(None)

		cf = conffile
		for conffile in files:
			if conffile != None and os.access(conffile, os.R_OK):
				break

		if conffile == None:
			debug("FATAL: Can't find or read %s." % (cf), LOG_EMERG)
			return

		if not conf["runtime"]["offline"]:
			debug("Config file %s found." % conffile, LOG_INFO)

	if childname: debug("Tconfig loop started", LOG_INFO)
	
	while conf["runtime"]["endtime"] == 0:
		if not os.access(conffile, os.R_OK):
			debug("FATAL: Can't access %s." % (conffile), LOG_CRIT)
			time.sleep(60)
			continue
		if conf["runtime"]["conftime"] < os.stat(conffile)[8]:
			if conf["main"]["confbackup"] and conf["runtime"]["conftime"] > 0:
				config_save(conffile)
			config_load(conffile)
			if conf["runtime"]["offline"]:
				conf["main"]["verbose"] = conf["main"]["offline"]

			if childname:
				debug("Configuration %s reloaded" % (conffile), LOG_NOTICE)
			conf["runtime"]["conftime"] = os.stat(conffile)[8]
			conf["runtime"]["conffile"] = conffile

			conf["runtime"]["confpath"] = conf["runtime"]["conffile"][0:conf["runtime"]["conffile"].rfind("/")]

			if conf["main"]["sspammdir"] and conf["main"]["sspammdir"][0] not in ["/", "."]: conf["main"]["sspammdir"] = "%s/%s" % (conf["runtime"]["confpath"], conf["main"]["sspammdir"])

			for s in ["logfile", "rrdfile", "crcfile", "savedir", "pid"]:
				if conf["main"].has_key(s) and conf["main"][s]:
					if conf["main"][s] == ".":
						conf["main"][s] = conf["main"]["sspammdir"]
					if conf["main"]["sspammdir"]:
						conf["main"][s] = re.sub("%s", conf["main"]["sspammdir"], conf["main"][s])
					conf["main"][s] = re.sub("%n", conf["main"]["name"], conf["main"][s])
					conf["main"][s] = re.sub("%c", conf["runtime"]["confpath"], conf["main"][s])
					conf["main"][s] = re.sub("%h", hostname, conf["main"][s])

					if conf["main"][s] and conf["main"][s][0] not in ["/", "."]: conf["main"][s] = "%s/%s" % (conf["main"]["sspammdir"], conf["main"][s])

			if not conf["runtime"]["offline"] and conf["main"]["savedir"]:
				try: mkdir(conf["main"]["savedir"])
				except: pass

			debug("""Files and paths used:
confpath:\t%s
sspammdir:\t%s
savedir:\t%s
pidfile:\t%s
rrdfile:\t%s
crcfile:\t%s
logfile:\t%s
""" % (
conf["runtime"]["confpath"],
conf["main"]["sspammdir"],
conf["main"]["savedir"],
conf["main"]["pid"],
conf["main"]["rrdfile"],
conf["main"]["crcfile"],
conf["main"]["logfile"],
), LOG_DEBUG)

		else:
			if childname and not (conf["main"]["pid"] and os.path.exists(conf["main"]["pid"])):
				debug("Pid file %s missing, quiting." % (conf["main"]["pid"]), LOG_NOTICE)
				conf["runtime"]["endtime"] = -1
				break
			else:
				time.sleep(2)
		if not childname: break
		time.sleep(1)
	if childname:
		debug("Config thread quited", LOG_INFO)
		if not (conf["main"]["pid"] and os.path.exists(conf["main"]["pid"])):
			cleanquit()
	return

def Tlogger(childname=None):
	loglines.insert(0, "sighup")
	logfile = None

	if childname: debug("Tlogger loop started", LOG_INFO)
	try:
		while conf["runtime"]["endtime"] == 0 or len(loglines) > 0:
			needflush = None
			while len(loglines) > 0:
				line = loglines.pop(0)
				if line == "sighup":
					if logfile: logfile.close()
					if conf["main"]["logfile"]:
						logpath=conf["main"]["logfile"][0:conf["main"]["logfile"].rfind("/")+1]
						if not os.path.exists(logpath):
							mkdir(logpath)
						logfile = open(conf["main"]["logfile"], "a")
						conf["runtime"]["logtime"] = os.stat(conf["main"]["logfile"])[8]
					continue
				if logfile: logfile.write(line+"\n")
				if conf["main"]["verbose"] == 7:
					print(line)
				needflush = True
			if needflush:
				if logfile: logfile.flush()
				sys.stdout.flush()
			if not childname: break
			time.sleep(1)
			try:
				if conf["runtime"]["logtime"] != os.stat(conf["main"]["logfile"])[8] and "sighup" not in loglines:
					loglines.append("sighup")
				if conf["main"]["logfile"]: conf["runtime"]["logtime"] = os.stat(conf["main"]["logfile"])[8]
			except:
				if "sighup" not in loglines: loglines.append("sighup")

		if logfile: logfile.close()
		if childname: debug("Logger thread quited", LOG_INFO)
		return
	except:
		pass
	debug("Logger thread quited", LOG_INFO)
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

## Thread that keeps RRD information updated, should update RRD info every 5 minutes or so.
def Trrd(childname=None):
	global hostname, userrd

	if childname != "RRD": return
	debug("Create RRD child thread", LOG_DEBUG)
	conf["runtime"]["rrd"] = { "ham": 0, "unsure": 0, "spam": 0, }
	if not os.path.exists(conf["main"]["rrdfile"]):
		debug("RRD Create: %s" % (conf["main"]["rrdfile"]), LOG_NOTICE)
		rrdtool.create(conf["main"]["rrdfile"], "-s 300", 
			'DS:pass:GAUGE:600:-1:65535',
			'DS:flag:GAUGE:600:-1:65535',
			'DS:block:GAUGE:600:-1:65535',
			'RRA:AVERAGE:0.5:1:288',
			'RRA:AVERAGE:0.5:12:336',
			'RRA:AVERAGE:0.5:288:365',
		)

# Clock specific things need to do, because vmware clock skew/jumps ?
	while conf["runtime"]["endtime"] == 0:
		if childname and not (conf["main"]["pid"] and os.path.exists(conf["main"]["pid"])): break
		if (time.strftime('%M')[-1] in ["0", "5"]) and (int(time.strftime('%S')) < 10):
			timestamp=int(time.time())
			tmp=conf["runtime"]["rrd"].copy()
			conf["runtime"]["rrd"] = { "ham": 0, "unsure": 0, "spam": 0, }
			try:
				rrdtool.update(conf["main"]["rrdfile"], "%s:%d:%d:%d" % (timestamp, tmp["ham"], tmp["unsure"], tmp["spam"]))
				debug("RRD Update %s: Ham: %s, Unsure: %s, Spam: %s" % (timestamp, tmp["ham"], tmp["unsure"], tmp["spam"]), LOG_ERR)
			except:
				debug("RRD Update: %s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
# Statistics updated, sleep for about 4 minutes.
			time.sleep(300-60)
		elif int(time.strftime('%S')) >= 58:
			time.sleep(0.2)
		elif int(time.strftime('%S')) >= 40:
			time.sleep(1)
		else:
			time.sleep(10)
	debug("RRD thread quited", LOG_INFO)
	return

###
### Main Function
###
def cleanquit():
	global conf

	debug("cleanquit()", LOG_INFO)
	rm(conf["main"]["pid"])
	conf["runtime"]["endtime"] = "%.0f" % time.time()
	debug("Spam Filter runtime was %.0f seconds" % (int(conf["runtime"]["endtime"])-int(conf["runtime"]["starttime"])), LOG_INFO)

	if conf["main"]["verbose"] in [3, 4, 5]:
		for a in ['confpath','conftime','logtime']:
			if conf["runtime"].has_key(a): del conf["runtime"][a]
		print(show_vars(conf["runtime"]))
	sys.stdout.flush()
	time.sleep(1)
	os._exit(0)

def main():
	global conf, hostname, userrd, usedns

	Tconfig()
	if(not makepid(conf["main"]["pid"])): cleanquit()

	if os.path.exists(conf["main"]["crcfile"]) and os.access(conf["main"]["crcfile"], os.R_OK):
		debug("Loading CRC database", LOG_NOTICE)
#		try:
		msgbase = load_vars(conf["main"]["crcfile"])
#		except:
#			pass

	if conf["main"]["childs"]:
		thread.start_new_thread(Tconfig,("Configuration Loader",))
	else:
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

#	if(not makepid(conf["main"]["pid"])): cleanquit()

	Milter.factory = SpamMilter
	Milter.set_flags(ADDRCPT + DELRCPT + ADDHDRS + CHGHDRS + CHGBODY)

	debug("Spam Filter started", LOG_INFO)
#	if not userrd: debug("WARNING! rrdtool module not loaded, RRD disabled", LOG_ALERT)
	if not usedns: debug("WARNING! DNS module not loaded, DNS functions (like RBL) disabled!", LOG_ALERT)

## It seems that under vmware systems there is sometimes quite big 'sleeps'
## on system. For some reason clock can jump few seconds ahead, so we can't
## use "time.sleep" as acurate. That's why we need to use our own acurate
## clock thread, that calls functions like RRD update.
	if conf["main"]["childs"]:
#		thread.start_new_thread(Tclock,("Clock",))
		thread.start_new_thread(Tlogger,("Logger",))
		if userrd:
			thread.start_new_thread(Trrd,("RRD",))
		thread.start_new_thread(Tcrc,("CRC",))
#		thread.start_new_thread(Tstats,("Stats",))
#	else:
#		debug("Logging, RRD, etc. are disabled in foreground mode.", LOG_ALERT)

	try:
		Milter.runmilter(conf["main"]["name"],conf["main"]["port"],300)
	except SystemExit:
		pass
	except:
		debug("%s: %s" % (sys.exc_type, sys.exc_value), LOG_ERR)
	cleanquit()

##
##
##
class test:
	def __init__(self, file, verbose = 1):
		if file.find(".") > 0:
			file=file[0:file.rfind(".")]
		if not os.path.exists(file):
			if os.path.exists("%s.var" % file):
				file = "%s.var" % file
			else:
				print("File %s not found!" % file)
				sys.exit(2)

		# Load Configuration
		conf["main"]["verbose"] = 4
		conf["runtime"]["offline"] = True
		conf["main"]["verbose"] = conf["main"]["offline"]
		Tconfig()
		# Setup our debugging
		conf["main"]["savedir"] = None
		conf["main"]["tmpdir"] = "."

		# Load mail from file with variables
		self.mail = load_vars("%s" % file)
		# Open temp file and write raw message into it

		if self.mail.has_key("raw") and self.mail["raw"]:
			self.tmp = open("%s.tmp" % file, "w+b")
			self.tmp.write(self.mail["raw"])
			self.tmp.close()
			# Reopen tmp file as read-only and move to end
			# Now we should have system like when online
			self.tmp = open("%s.tmp" % file, "r")
			# Seek to end-of-file
			#self.tmp.seek(0,2)
			# Seek to begining-of-file
			self.tmp.seek(0)

	def feed2milter(self):
		m = SpamMilter()
		# Read connect information from variables, and simulate
		# SMTP-connection.
		if not self.mail["received"][1].has_key("dns"):
			self.mail["received"][1]["dns"] = "[%s]" % self.mail["received"][1]["ip"]
		m.connect(self.mail["received"][1]["dns"],None,[self.mail["received"][1]["ip"]])
		if self.mail["received"][1].has_key("helo"):
			m.hello(self.mail["received"][1]["helo"])
		else:
			m.hello(self.mail["received"][1]["dns"])
		if type(self.mail["from"]) is list:
			m.envfrom("<%s>" % self.mail["from"][0])
		else:
			m.envfrom("<%s>" % self.mail["from"])
		if type(self.mail["to"]) is list:
			for r in self.mail["to"]:
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
				m.header(oline[0:oline.find(":")],oline[oline.find(":")+2:-1])
				oline=line
			if len(line) < 2: break
		m.eoh()
		# Feed maximum of 2MB of message to milter, should we increase this?
		m.body(self.tmp.read(1024*1024*2))
		# Now we have done everything as in 'online'
		m.eom()
		m.close()
		if self.tmp:
			self.tmp.close()
			rm(self.tmp.name)

	def run(self, arg=None):
		if arg == "test":
			self.feed2milter()
		sys.exit(0)

###
### Start
###
if __name__ == "__main__":
	tmp = None
	conf["runtime"]["starttime"] = "%.0f" % time.time()
	conf["runtime"]["startdir"] = os.getcwd()

	os.nice(5)
## I do use fi_FI.UTF-8 
#	locale.setlocale(locale.LC_CTYPE, 'en_US.UTF-8')
#	locale.setlocale(locale.LC_CTYPE, locale.normalize('iso-8859-15'))
	locale.setlocale(locale.LC_CTYPE, 'fi_FI.UTF-8')
	try:
		hostname = gethostname()[0:gethostname().index('.')]
	except:
		hostname = gethostname()

#       debug("Use RRD: %s" % (userrd), LOG_INFO)
		debug("Use DNS: %s" % (usedns), LOG_INFO)
	conf["runtime"]["bindir"] = sys.argv[0][0:sys.argv[0].rfind("/")]
	if not sys.argv[1:]:
		main()
	elif sys.argv[1:][0] == "pid":
		Tconfig()
		print(conf["main"]["pid"])
		sys.exit(0)
	elif sys.argv[1:][0] == "sspammdir":
		Tconfig()
		print(conf["main"]["sspammdir"])
		sys.exit(0)
	elif sys.argv[1:][0] == "test":
		if len(sys.argv) >= 3: test(sys.argv[2:][0]).run(sys.argv[1:][0])
	elif os.path.exists(sys.argv[1:][0]):
		test(sys.argv[1:][0]).run("test")
	else:
		print("""Without parameters spamfilter starts.

Parameters usage:
  test	- Give .var file as parameter, this does all same tests on that
	  saved mail as it would be done in online mode. Runs on verbose
	  debug mode.
""")
		sys.exit(1)
sys.exit(0)
