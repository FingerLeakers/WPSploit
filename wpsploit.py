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

        source = sys.argv[1]

        # Recursively test all files
        if os.path.isdir(source):
            print("Scanning directory: {}".format(source))
            files = self.recursiveRead(source, '*.php')
            print("Found {} files. \n".format(len(files)))
            for file in files:
                self.testFile(file)

        # Test single file
        else:
            file = self.control(source)
            self.testFile(file)
            
    # Test file against common vulnerabilities
    def testFile(self, path):
        print("Testing file: {}".format(path))
        try:
            code = self.readfile(path)
            self.xss(code)
            self.sql(code)
            self.fid(code)
            self.fin(code)
            self.php(code)
            self.com(code)
            self.pce(code)
            self.ope(code)
            self.csrf(code)
        except Exception as e:
            raise

    def csrf(self, code):
        blacklist = [r'wp_nonce_field\(\S*\)', r'wp_nonce_url\(\S*\)',
                     r'wp_verify_nonce\(\S*\)', r'check_admin_referer\(\S*\)']
        for bl in blacklist:
            for cd in code:
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    print "{}- Possibile Cross-Site Request Forgery{} ==> {}{}{}".format(colors.GREEN, colors.END, colors.RED, pattern[0], colors.END)

    def ope(self, code):
        for cd in code:
            pattern = re.findall(r"wp_redirect\(\S*\)", cd, re.I)
            if pattern != []:
                print "{}- Possibile Open Redirect{} ==> {}{}{}".format(colors.GREEN, colors.END, colors.RED, pattern[0], colors.END)

    def pce(self, code):
        blacklist = [r'eval\(\S*\)', r'assert\(\S*\)', r'preg_replace\(\S*\)']
        for bl in blacklist:
            for cd in code:
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    print "{}- Possibile PHP Command Execution{} ==> {}{}{}".format(colors.GREEN, colors.END, colors.RED, pattern[0], colors.END)

    def com(self, code):
        blacklist = [r'system\(\S*\)', r'exec\(\S*\)',
                     r'passthru\(\S*\)', r'shell_exec\(\S*\)']
        for bl in blacklist:
            for cd in code:
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    print "{}- Possibile Command Execution{} ==> {}{}{}".format(colors.GREEN, colors.END, colors.RED, pattern[0], colors.END)

    def php(self, code):
        for cd in code:
            pattern = re.findall(r"unserialize\(\S*\)", cd, re.I)
            if pattern != []:
                print "{}- Possibile PHP Object Injection{} ==> {}{}{}".format(colors.GREEN, colors.END, colors.RED, pattern[0], colors.END)

    def fin(self, code):
        blacklist = [r'include\(\S*\)', r'require\(\S*\)',
                     r'include_once\(\S*\)', r'require_once\(\S*\)', r'fread\(\S*\)']
        for bl in blacklist:
            for cd in code:
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    print "{}- Possibile File Inclusion{} ==> {}{}{}".format(colors.GREEN, colors.END, colors.RED, pattern[0], colors.END)

    def fid(self, code):
        blacklist = [r'file\(\S*\)', r'readfile\(\S*\)',
                     r'file_get_contents\(\S*\)']
        for bl in blacklist:
            for cd in code:
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    print "{}- Possibile File Download{} ==> {}{}{}".format(colors.GREEN, colors.END, colors.RED, pattern[0], colors.END)

    def sql(self, code):
        blacklist = [r'\$wpdb->query\(\S*\)', r'\$wpdb->get_var\(\S*\)', r'\$wpdb->get_row\(\S*\)', r'\$wpdb->get_col\(\S*\)',
                     r'\$wpdb->get_results\(\S*\)', r'\$wpdb->replace\(\S*\)', r'esc_sql\(\S*\)', r'escape\(\S*\)', r'esc_like\(\S*\)',
                     r'like_escape\(\S*\)']
        for bl in blacklist:
            for cd in code:
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    print "{}- Possibile Sql Injection ==> {}{}{}".format(colors.GREEN, colors.END, colors.RED, pattern[0], colors.END)

    def xss(self, code):
        blacklist = [r'\$_GET\[\S*\]', r'\$_POST\[\S*\]', r'\$_REQUEST\[\S*\]', r'\$_SERVER\[\S*\]', r'\$_COOKIE\[\S*\]',
                     r'add_query_arg\(\S*\)', r'remove_query_arg\(\S*\)']
        for bl in blacklist:
            for cd in code:
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    print "{}- Possibile Cross-Site Scripting{} ==> {}{}{}".format(colors.GREEN, colors.END, colors.RED, pattern[0], colors.END)

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
        msg = "# python %s plugintest.php" % (sys.argv[0])
        msg += "\n"
        print(msg)
        exit()

    def banner(self):
        lin = "#"
        msg = "\n"
        msg += (lin * 40)
        msg += "\n - Wodpress Plugin Code Scanner  "
        msg += "\n - Coded by Momo Outaadi (@m4ll0k)\n"
        msg += (lin * 40)
        msg += "\n"
        print(msg)


if __name__ == "__main__":
    try:
        wpsploit().main()
    except KeyboardInterrupt, e:
        exit()
