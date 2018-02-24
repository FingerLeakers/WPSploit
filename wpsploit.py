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

import os
import sys
import re
import glob
import fnmatch
import json

BANNER = r"""
 __      ____________  _________       __          __   __  
/  \    /  \______   \/   _____/_____ |  |   ____ |__|_/  |__ 
\   \/\/   /|     ___/\_____  \\____ \|  |  /  _ \|  |_   ___|
 \        / |    |    /        \  |_) |  |_(  (_) )  | |  |
  \__/\  /  |____|   /_______  /   __/|____/\____/|__| |__|
       \/                    \/|__|

Aggressive Code Scanner for WordPress Themes/Plugins

Author: Momo (m4ll0k) Outaadi 
Contributors: Filippo (b4dnewz) Conti
"""

class colors(object):
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    END = "\033[0m"
    
# Vulnerabilities References
# https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet
class wpsploit(object):
    def main(self):
        self.banner()
        if len(sys.argv) <= 1:
            self.usage()

        result = []
        source = sys.argv[1]
        
        # Recursively test all files
        if os.path.isdir(source):
            print("Scanning directory: {}".format(source))
            files = self.recursiveRead(source, '*.php')
            print("Found {} files with php extension.\n".format(len(files)))
            for file in files:
                res = self.testFile(file)
                result.append(res)

        # Test single file
        else:
            file = self.control(source)
            res = self.testFile(file)
            result.append(res)
    
    def printLine(self, line, label, value):
        line = " {}[L{}]{}".format(colors.GREEN, line, colors.END)
        label = "{}{}{}".format(colors.GREEN, label, colors.END)
        value = "{}{}{}".format(colors.RED, value, colors.END)
        print "{} Possibile {} ==> {}".format(line, label, value)
    
    # Test file against common vulnerabilities
    def testFile(self, path):
        print("Testing file: {}".format(path))
        res = {
            "name": path,
            "total": 0,
            "data": {
                "xss": [],
                "sql": [],
                "fid": [],
                "fin": [],
                "php": [],
                "com": [],
                "auth": [],
                "pce": [],
                "ope": [],
                "csrf": []
            }
        }
        try:
            code = self.readfile(path)
            res['data']['xss'] = self.xss(code)
            res['data']['sql'] = self.sql(code)
            res['data']['fid'] = self.fid(code)
            res['data']['fin'] = self.fin(code)
            res['data']['php'] = self.php(code)
            res['data']['com'] = self.com(code)
            res['data']['auth'] = self.auth(code)
            res['data']['pce'] = self.pce(code)
            res['data']['ope'] = self.ope(code)
            res['data']['csfr'] = self.csrf(code)
            # Get total possible vulnerabilities
            res['total'] = sum(len(arr) for arr in res['data'].values())
            return res
        except Exception as e:
            raise
    
    # Check for Cross Site Request Forgery
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#cross-site-request-forgery-csrf
    def csrf(self, code):
        blacklist = [r'wp_nonce_field\(\S*\)', r'wp_nonce_url\(\S*\)',
                     r'wp_verify_nonce\(\S*\)', r'check_admin_referer\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    self.printLine(idx, "Cross-Site Request Forgery", pattern[0])
        return vulns
    
    # Check for Open Redirect
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#open-redirect
    def ope(self, code):
        vulns = []
        for idx, cd in enumerate(code):
            pattern = re.findall(r"wp_redirect\(\S*\)", cd, re.I)
            if pattern != []:
                vulns.append({"line": idx, "match": pattern[0] })
                self.printLine(idx, "Open Redirect", pattern[0])
        return vulns
        
    # Check for PHP Code Execution
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#php-code-execution
    def pce(self, code):
        blacklist = [r'eval\(\S*\)', r'assert\(\S*\)', r'preg_replace\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    self.printLine(idx, "PHP Code Execution", pattern[0])
        return vulns
    
    # Check for Command Execution
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#command-execution
    def com(self, code):
        blacklist = [r'system\(\S*\)', r'exec\(\S*\)',
                     r'passthru\(\S*\)', r'shell_exec\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    self.printLine(idx, "Command Execution", pattern[0])
        return vulns
    
    # Check for Authorization Hole
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#authorisation
    def auth(self, code):
        blacklist = [r'is_admin\(\S*\)', r'is_user_admin\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    self.printLine(idx, "Authorization Hole", pattern[0])
        return vulns
        
    # Check for PHP Object Injection
    def php(self, code):
        vulns = []
        for idx, cd in enumerate(code):
            pattern = re.findall(r"unserialize\(\S*\)", cd, re.I)
            if pattern != []:
                vulns.append({"line": idx, "match": pattern[0] })
                self.printLine(idx, "PHP Object Injection", pattern[0])
        return vulns
        
    # Check for File Inclusion
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#file-inclusion
    def fin(self, code):
        blacklist = [r'include\(\S*\)', r'require\(\S*\)',
                     r'include_once\(\S*\)', r'require_once\(\S*\)', r'fread\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    self.printLine(idx, "File Inclusion", pattern[0])
        return vulns
    
    # Check for File Download
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#file-download
    def fid(self, code):
        blacklist = [r'file\(\S*\)', r'readfile\(\S*\)',
                     r'file_get_contents\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    self.printLine(idx, "File Download", pattern[0])
        return vulns
    
    # Check for Sql Injection
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#sql-injection
    def sql(self, code):
        blacklist = [r'\$wpdb->query\(\S*\)', r'\$wpdb->get_var\(\S*\)', r'\$wpdb->get_row\(\S*\)', r'\$wpdb->get_col\(\S*\)',
                     r'\$wpdb->get_results\(\S*\)', r'\$wpdb->replace\(\S*\)', r'esc_sql\(\S*\)', r'escape\(\S*\)', r'esc_like\(\S*\)',
                     r'like_escape\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    self.printLine(idx, "Sql Injection", pattern[0])
        return vulns
    
    # Check for Cross-Site Scripting
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#cross-site-scripting-xss-tips
    def xss(self, code):
        blacklist = [r'\$_GET\[\S*\]', r'\$_POST\[\S*\]', r'\$_REQUEST\[\S*\]', r'\$_SERVER\[\S*\]', r'\$_COOKIE\[\S*\]',
                     r'add_query_arg\(\S*\)', r'remove_query_arg\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    self.printLine(idx, "Cross-Site Scripting", pattern[0])
        return vulns
        
    def control(self, filename):
        if not filename.endswith('.php'):
            self.usage()
        else:
            return filename

    def readfile(self, filename):
        codelist = []
        try:
            file = open(filename, "rb+")
            for line in file.readlines():
                line = line.split('\n')[0]
                codelist.append(line)
            return codelist
        except IOError, e:
            raise

    def recursiveRead(self, rootdir, pattern):
        matches = []
        for root, dirnames, filenames in os.walk(rootdir):
            for filename in fnmatch.filter(filenames, pattern):
                matches.append(os.path.join(root, filename))
        return matches

    def usage(self):
        print("Usage: $ python wpsploit.py <file|dir> \n")
        exit()

    def banner(self):
        print(BANNER)

# Run the script
if __name__ == "__main__":
    try:
        wpsploit().main()
    except KeyboardInterrupt, e:
        exit()
