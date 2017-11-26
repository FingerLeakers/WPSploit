#!/usr/bin/env python
# -*- Coding: UTF-8 -*-
#
# Copyright (c) 2017 @m4ll0k
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import re 
import sys

# https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet

class wpsploit(object):
	def main(self):
		try:
			if len(sys.argv) <= 1:
				self.usage()
			self.banner()
			code = self.readfile( self.control( sys.argv[1] ) )
			self.xss( code )
			self.sql( code )
			self.fid( code )
			self.fin( code )
			self.php( code )
			self.com( code )
			self.pce( code )
			self.ope( code )
			self.csrf( code )
		except Exception,e:
			raise

	def csrf(self,code):
		# check cross site request forgery
		print "%sChecking Cross-Site Request Forgery...%s"%("\033[1;32m","\033[0m")
		blacklist =  [r'wp_nonce_field\(\S*\)',r'wp_nonce_url\(\S*\)',r'wp_verify_nonce\(\S*\)',r'check_admin_referer\(\S*\)']
		for bl in blacklist:
			for cd in code:
				pattern = re.findall( bl,cd,re.I )
				if pattern != []:
					print "\t{}- Possibile Cross-Site Request Forgery{} ==> {}{}{}".format( "\033[1;34m","\033[0m","\033[1;31m",pattern[0],"\033[0m" )

	def ope(self,code):
		# check open redirect vulns
		print "%sChecking Open Redirect...%s"%("\033[1;32m","\033[0m")
		for cd in code:
			pattern = re.findall( r"wp_redirect\(\S*\)",cd,re.I )
			if pattern != []:
				print "\t{}- Possibile Open Redirect{} ==> {}{}{}".format( "\033[1;34m","\033[0m","\033[1;31m",pattern[0],"\033[0m" )

	def pce(self,code):
		# check php command execution
		print "%sChecking PHP Code Execution...%s"%("\033[1;32m","\033[0m")
		blacklist = [r'eval\(\S*\)',r'assert\(\S*\)',r'preg_replace\(\S*\)']
		for bl in blacklist:
			for cd in code:
				pattern = re.findall( bl,cd,re.I )
				if pattern != []:
					print "\t{}- Possibile PHP Command Execution{} ==> {}{}{}".format( "\033[1;34m","\033[0m","\033[1;31m",pattern[0],"\033[0m" ) 

	def com(self,code):
		# check command execution
		print "%sChecking Command Execution...%s"%("\033[1;32m","\033[0m")
		blacklist = [r'system\(\S*\)',r'exec\(\S*\)',r'passthru\(\S*\)',r'shell_exec\(\S*\)']
		for bl in blacklist:
			for cd in code:
				pattern = re.findall( bl,cd,re.I )
				if pattern != []:
					print "\t{}- Possibile Command Execution{} ==> {}{}{}".format( "\033[1;34m","\033[0m","\033[1;31m",pattern[0],"\033[0m" )

	def php(self,code):
		# check php object injection vuln
		print "%sChecking PHP Object Injection...%s"%("\033[1;32m","\033[0m")
		for cd in code:
			pattern = re.findall( r"unserialize\(\S*\)",cd,re.I )
			if pattern != []:
				print "\t{}- Possibile PHP Object Injection{} ==> {}{}{}".format( "\033[1;34m","\033[0m","\033[1;31m",pattern[0],"\033[0m" )

	def fin(self,code):
		# check file inclusion vuln
		print "%sChecking File Inclusion...%s"%("\033[1;32m","\033[0m")
		blacklist = [r'include\(\S*\)',r'require\(\S*\)',r'include_once\(\S*\)',r'require_once\(\S*\)',r'fread\(\S*\)']
		for bl in blacklist:
			for cd in code:
				pattern = re.findall( bl,cd,re.I )
				if pattern != []:
					print "\t{}- Possibile File Inclusion{} ==> {}{}{}".format( "\033[1;34m","\033[0m","\033[1;31m",pattern[0],"\033[0m" )

	def fid(self,code):
		# check file download vuln
		print "%sChecking File Download...%s"%("\033[1;32m","\033[0m")
		blacklist = [r'file\(\S*\)',r'readfile\(\S*\)',r'file_get_contents\(\S*\)']
		for bl in blacklist:
			for cd in code:
				pattern = re.findall( bl,cd,re.I )
				if pattern != []:
					print "\t{}- Possibile File Download{} ==> {}{}{}".format( "\033[1;34m","\033[0m","\033[1;31m",pattern[0],"\033[0m" )

	def sql(self,code):
		# check sql injection vuln
		print "%sChecking SQL Injection...%s"%("\033[1;32m","\033[0m")
		blacklist = [r'\$wpdb->query\(\S*\)',r'\$wpdb->get_var\(\S*\)',r'\$wpdb->get_row\(\S*\)',r'\$wpdb->get_col\(\S*\)',
		             r'\$wpdb->get_results\(\S*\)',r'\$wpdb->replace\(\S*\)',r'esc_sql\(\S*\)',r'escape\(\S*\)',r'esc_like\(\S*\)',
		             r'like_escape\(\S*\)']
		for bl in blacklist:
			for cd in code:
				pattern = re.findall( bl,cd,re.I )
				if pattern != []:
					print "\t{}- Possibile Sql Injection ==> {}{}{}".format( "\033[1;34m","\033[0m","\033[1;31m",pattern[0],"\033[0m" )

	def xss(self,code):
		# check cross site scripting vuln
		print "%sChecking Cross-Site Scripting...%s"%("\033[1;32m","\033[0m")
		blacklist = [r'\$_GET\[\S*\]',r'\$_POST\[\S*\]',r'\$_REQUEST\[\S*\]',r'\$_SERVER\[\S*\]',r'\$_COOKIE\[\S*\]',
		             r'add_query_arg\(\S*\)',r'remove_query_arg\(\S*\)']
		for bl in blacklist:
			for cd in code:
				pattern = re.findall( bl,cd,re.I )
				if pattern != []:
					print "\t{}- Possibile Cross-Site Scripting{} ==> {}{}{}".format( "\033[1;34m","\033[0m","\033[1;31m",pattern[0],"\033[0m" )

	def control(self,filename):
		if not filename.endswith( '.php' ):
			self.usage( )
		else:
			return filename

	def readfile(self,filename):
		codelist = []
		try:
			file = open( filename,"rb+" )
			for line in file.readlines( ):
				line = line.split( '\n' )[0]
				codelist.append( line )
			return codelist
		except IOError,e:
			raise

	def usage(self):
		self.banner()
		msg = "# python %s plugintest.php"%(sys.argv[0])
		msg += "\n"
		print ( msg )
		exit( )
	
	def banner(self):
		lin = "#"
		msg = "\n"
		msg += ( lin * 40 )
		msg += "\n - Wodpress Plugin Code Scanner  "
		msg += "\n - Coded by Momo Outaadi (@m4ll0k)\n"
		msg += (lin * 40 )
		msg += "\n"
		print ( msg )

if __name__ == "__main__":
	try:
		wpsploit().main()
	except KeyboardInterrupt,e:
		exit( )
