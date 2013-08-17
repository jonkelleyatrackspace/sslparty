SSLyze
======

Fast and full-featured SSL scanner.


Description
-----------

SSLyze is a Python tool that can analyze the SSL configuration of a server by
connecting to it. It is designed to be fast and comprehensive, and should help
organizations and testers identify misconfigurations affecting their SSL
servers.

Key features include:
* Multi-processed and multi-threaded scanning (it's fast)
* SSL 2.0/3.0 and TLS 1.0/1.1/1.2 compatibility
* Performance testing: session resumption and TLS tickets support
* Security testing: weak cipher suites, insecure renegotiation, CRIME and more
* Server certificate validation and revocation checking through OCSP stapling
* Support for StartTLS handshakes on SMTP, XMPP, LDAP, POP, IMAP and FTP
* Support for client certificates when scanning servers that perform mutual authentication
* XML output to further process the scan results
* And much more !


Installation
------------

SSLyze requires Python 2.7; the supported platforms are Windows 7 32/64 bits, 
Linux 32/64 bits and OS X 64 bits.

SSLyze is statically linked with OpenSSL 1.0.1e. For this reason, the easiest 
way to run SSLyze is to download one the pre-compiled packages available at
http://nabla-c0d3.github.io/blog/2013/08/14/sslyze-v0-dot-7-released/.


Usage
-----

### Command line options

The following command will provide the list of available command line options:
	$ python sslyze.py -h


### Sample command line:

	$ python sslyze.py --regular www.isecpartners.com:443 www.google.com

See the test folder for additional examples.


Build
-----

SSLyze is all Python code but since version 0.7, it uses a custom OpenSSL 
wrapper written in C. The pre-compiled packages contain SSLyze's code and a 
compiled version of this wrapper, statically linked with OpenSSL and Zlib. This 
wrapper is hosted at https://github.com/nabla-c0d3/nassl.


License
--------

GPLv2 - See LICENSE.txt.
