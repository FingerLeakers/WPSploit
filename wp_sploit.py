#!/usr/bin/env python 
# -*- Coding:UTF-8 -*-
# Momo Outaadi (@m4ll0k)

 
import sys 
import re

def getfile(filename):
	try:
		code_list = []
		file = open(filename,"r")
		for f in file.readlines():
			code_list.append(f.split('\n')[0])
		return code_list
	except Exception,e:
		raise

def cross_site_scripting(contents):
	print "{}Checking Cross Site Scripting...{}".format("\033[1;34m","\033[0m")
	black = [r'\$_GET\[\S*\]',r'\$_POST\[\S*\]',r'\$_REQUEST\[\S*\]',r'\$_SERVER\[\S*\]',r'\$_COOKIE\[\S*\]']
	try:
		for blacklist in black:
			for content in contents:
				pattern = re.findall(blacklist,content,re.I)
				if pattern != []:
					print "\t- {}Possibility Cross Site Scripting{} ==> {}{}{}".format("\033[1;32m","\033[0m","\033[1;31m",pattern[0],"\033[0m")
	except Exception,e:
		raise

def sql_injection(contents):
	print "{}Checking Sql Injection...{}".format("\033[1;34m","\033[0m")
	try:
		for content in contents:
			pattern = re.findall(r'\$wpdb->\S*',content,re.I)
			if pattern != []:
				print "\t- {}Possibility Sql Injection{} ==> {}{}{}".format("\033[1;32m","\033[0m","\033[1;31m",pattern[0],"\033[0m")
	except Exception,e:
		raise

def file_inclusion(contents):
	print "{}Checking File Inclusion...{}".format("\033[1;34m","\033[0m")
	black = [r'include\(\S*\)',r'require\(\S*\)',r'include_once\(\S*\)',r'require_once\(\S*\)',r'fread\(\S*\)']
	try:
		for blacklist in black:
			for content in contents:
				pattern = re.findall(blacklist,content,re.I)
				if pattern != []:
					print "\t- {}Possibility File Inclusion{} ==> {}{}{}".format("\033[1;32m","\033[0m","\033[1;31m",pattern[0],"\033[0m")
	except Exception,e:
		raise

def command_execution(contents):
	print "{}Checking Command Execution...{}".format("\033[1;34m","\033[0m")
	black = [r'system\(\S*\)',r'exec\(\S*\)',r'passthru\(\S*\)',r'shell_exec\(\S*\)']
	try:
		for blacklist in black:
			for content in contents:
				pattern = re.findall(blacklist,content,re.I)
				if pattern != []:
					print "\t- {}Possibility Command Execution{} ==> {}{}{}".format("\033[1;32m","\033[0m","\033[1;31m",pattern[0],"\033[0m")
	except Exception,e:
		raise

def php_code_execution(contents):
	print "{}Checking PHP Code Execution...{}".format("\033[1;34m","\033[0m")
	black = [r'eval\(\S*\)',r'assert\(\S*\)',r'preg_replace\(\S*\)']
	try:
		for blacklist in black:
			for content in  contents:
				pattern = re.findall(blacklist,content,re.I)
				if pattern != []:
					print "\t- {}Possibility PHP Code Execution{} ==> {}{}{}".format("\033[1;32m","\033[0m","\033[1;31m",pattern[0],"\033[0m")
	except Exception,e:
		raise

def open_redirect(contents):
	print "{}Checking Open Redirect...{}".format("\033[1;34m","\033[0m")
	try:
		for content in contents:
			pattern = re.findall(r'wp_redirect()',content,re.I)
			if pattern != []:
				print "\t- {}Possibility Open Redirect{} ==> {}{}{}".format("\033[1;32m","\033[0m","\033[1;31m",pattern[0],"\033[0m")
	except Exception,e:
		raise

def cross_site_request_forgery(contents):
	print "{}Checking Cross Site Request Forgery...{}".format("\033[1;34m","\033[0m")
	black = [r'wp_nonce_field\(\S*\)',r'wp_nonce_url\(\S*\)',r'wp_verify_nonce\(\S*\)',r'check_admin_referer\(\S*\)']
	try:
		for blacklist in black:
			for content in contents:
				pattern = re.findall(blacklist,content,re.I)
				if pattern != []:
					print "\t- {}Possibile Cross Site Request Forgery{} ==> {}{}{}".format("\033[1;32m","\033[0m","\033[1;31m",pattern[0],"\033[0m")
	except Exception,e:
		raise

def ban():
	print "*******************************************"
	print "- Wordpress Plugin Find Common Vulns      *"
	print "-  Coded  by Momo Outaadi (@m4ll0k)       *"
	print "*******************************************"

def main():
	if len(sys.argv) <= 1:
		ban()
		print "\npython %s file_plugin.php\n"%(sys.argv[0])
		exit()
	try:
		if not sys.argv[1].endswith('.php'):
			ban()
			print "\npython %s file_plugin.php\n"%(sys.argv[0])
			exit()
		ban()
		contents = getfile(sys.argv[1])
		cross_site_scripting(contents)
		sql_injection(contents)
		file_inclusion(contents)
		command_execution(contents)
		php_code_execution(contents)
		open_redirect(contents)
		cross_site_request_forgery(contents)
	except Exception,e:
		raise
main()