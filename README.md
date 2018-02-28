## WPSploit

> Aggressive Code Scanner for Wordpress Themes/Plugins

![python](https://img.shields.io/badge/python-2.7-brightgreen.svg) ![license](https://img.shields.io/badge/license-GPL-brightgreen.svg)

This tool is intended for Penetration Testers who audit WordPress themes or plugins or developers who wish to audit their own WordPress code. This script should be used for learning purposes only. By downloading and running this script you take every responsibility for wrong or illegal uses of it.

For more informations about the vulnerabilities tested [click here](https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet).

[![demo](https://asciinema.org/a/SKPJtXGr04egsIOeELUMdPAkb.png)](https://asciinema.org/a/SKPJtXGr04egsIOeELUMdPAkb)

## Getting started
Download the code cloning the repository or via wget:
```
$ git clone https://github.com/m4ll0k/wpsploit.git
```
or
```
$ wget https://raw.githubusercontent.com/m4ll0k/wp_sploit/master/wpsploit.py
```

## Usage
Type `--help` or `-h` to get the usage information anytime:

```

 __      ____________  _________       __          __   __  
/  \    /  \______   \/   _____/_____ |  |   ____ |__|_/  |__ 
\   \/\/   /|     ___/\_____  \\____ \|  |  /  _ \|  |_   ___|
 \        / |    |    /        \  |_) |  |_(  (_) )  | |  |
  \__/\  /  |____|   /_______  /   __/|____/\____/|__| |__|
       \/                    \/|__|

Aggressive Code Scanner for WordPress Themes/Plugins

Author: Momo (m4ll0k) Outaadi 
Contributors: Filippo (b4dnewz) Conti

Usage: $ python wpsploit.py <file|dir> 

```
You can run it against a single file or a directory and it will test for common code vulnerabilities.
