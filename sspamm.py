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

from socket import gethostname


def main():
	return

if __name__ == "__main__":

	os.nice(5)
	locale.setlocale(locale.LC_CTYPE, 'en_US.UTF-8')

	try:
		hostname = gethostname()[0:gethostname().index('.')]
	except:
		hostname = gethostname()
	print hostname

	if not sys.argv[1:]:
		main()
	else:
		print """We need help here?"""
		sys.exit(1)

sys.exit(0)
