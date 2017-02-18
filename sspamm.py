#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""Semi's SPAM Milter
"""
__author__ = "Sami-Pekka Hallikas <semi@hallikas.com>"
__email__ = "semi@hallikas.com"
__date__ = "19 Feb 2017"
__version__ = "4.0-devel"

import sys

def main():
	return

if __name__ == "__main__":

	if not sys.argv[1:]:
		main()
	else:
		print """We need help here?"""
		sys.exit(1)

sys.exit(0)
