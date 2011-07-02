============
vmod_secdown
============

------------------------------
Varnish Secure Download Module
------------------------------

:Author: Aurelien Guillaume
:Date:   2011-07-01
:Version: 1.0
:Manual section: 3


SYNOPSIS
========

import secdown

DESCRIPTION
===========

For specific purposes, i had to imagine a way to use Varnish as a cache for
various files that should be protected against hotlinking/mass downloading.
Protection by the referer was not enough, so unique downloads links had to be generated.

I still wanted the files to be cached by Varnish.

This module is freely inspired from the functionnality described at
http://wiki.nginx.org/HttpSecureDownload and it should be perfectly
compatible with this implementation.

FUNCTIONS
=========

check_url
---------

Prototype
	check_url(STRING url, STRING secret, STRING expired_url, STRING error_url)
Return value
	STRING (URL that the user should be directed to)
Description
	Checks the validity of a link, given the information extracted from the link.
	Valid URL scheme:

	<final_url>/<md5_hash>/<expiration_timestamp>

	the md5 hash gets generated out of the following string:
	
	<final_url>/<secret>/<expiration_timestamp>

	So, you should make a regular expression that

	final_url is returned if the hash and the expiration are valid, and the link
	is not expired.

	expired_url is returned if the hash is valid, but the link has expired.
	
	error_url is returned if there's been another error (bad hash, bad url scheme...)

	secret is some random string which must be known by the nginx config and by the link generating script

	expiration_timestamp is a unix_timestamp (seconds since beginning of 1970) in hexadecimal format

Example
	set req.url = secdown.check_url(req.url, "h4ckme", "/expired.html", "/error.html") 
	
SEE ALSO
========

* vcl(7)
* varnishd(1)

COPYRIGHT
=========

This document is licensed under the same licence as Varnish
itself. See LICENCE for details.

* Copyright (c) 2011 BCS Technologies
