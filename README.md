## WPSploit - WordPress Plugin Code Scanner

This tool is intended for Penetration Testers who audit WordPress plugins or developers who wish to audit their own WordPress plugins. For more info [click here](https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet).

![screen_1](https://raw.githubusercontent.com/m4ll0k/wp_sploit/master/screen_1.png)

## Usage
```
$ git clone https://github.com/m4ll0k/wpsploit.git
$ cd wpsploit
$ python wpsploit.py plugin_file.php
```
or

```
$ wget https://raw.githubusercontent.com/m4ll0k/wp_sploit/master/wpsploit.py
$ python wpsploit.py plugin_file.php
```

## Example

```
$ wget https://plugins.svn.wordpress.org/analytics-for-woocommerce-by-customerio/trunk/admin/class-wccustomerio-admin.php
$ python wpsploit.py class-wccustomerio-admin.php
```
