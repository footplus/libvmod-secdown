============
vmod_secdown
============

------------------------------
Varnish Secure Download Module
------------------------------

:Author: Aurelien Guillaume
:Date:   2011-08-08
:Version: 1.1
:Manual section: 3


SYNOPSIS
========

import secdown

DESCRIPTION
===========

For specific purposes, i had to imagine a way to use Varnish as a cache for
various files that should be protected against hotlinking/mass downloading.
Protection by the referer was not enough, so unique downloads links had to be generated,
but I still wanted the files to be cached by Varnish.

So, this module is freely inspired from the functionnality described at
http://wiki.nginx.org/HttpSecureDownload and it should be compatible with this implementation.

At this stage, this module is mostly a proof-of-concept; it has only received minimal
testing and we have never used it in production. I will update this file if/when it reaches
a more usable status.

So far the module builds and runs on Linux--on other platforms, you are on your own.

Patches are welcome.

FUNCTIONS
=========

vmod_secdown implements the following calls:

check_url
---------

Prototype
	check_url(STRING protected_url, STRING secret, STRING expired_url, STRING error_url)

Return value
	STRING (URL that the user should be directed to)

Description
	Checks the validity of a protected URL. A protected URL looks like this:::

		http://hostname/path/to/protected/file/<md5_hash>/<expiration_timestamp>
	
	Optionnally, the check can be relaxed to a prefix instead of a full path:::

		http://hostname/path/to/protected/file/<md5_hash>/<expiration_timestamp>x<prefix_len>

	Since Varnish already does some processing on the URL, **req.url**, which does not contain
	the `http://hostname` part is probably a good candidate in your VCL scripts.

	**expiration_timestamp** is a 8-digit unix_timestamp (seconds since beginning of 1970) in hexadecimal format.
	
	**prefix_len** is a 4-digit hexadecimal number representing the maximal path len to consider for inclusion
	in MD5 hashs.
	
	**md5_hash** is a MD5 hash generated out of the following string, by your application:::
	
		/path/to/protected/file/<secret>/<expiration_timestamp>

	if **prefix_len** is set, the path will be cut to this number of bytes, and "x<prefix_len>" will be
	added to the string to be hashed. 

	The **secret** is some secret string of your choice, known only of your application,
	which will serve to generate the expiring links.

	The function **check_url** will return a string, which will be either:
		* **expired_url**, when the hash is valid, but the timestamp is in the past..
		* **error_url** if there's been another error (bad hash, bad url scheme, other internal errors)

Examples
	Protection of the /protected/ directory.::

		if (req.url ~ "^/protected/")
		{
			set req.url = secdown.check_url(req.url, "h4ckme", "/expired.html", "/error.html") 
		}
	
SEE ALSO
========

* vcl(7)
* varnishd(1)

COPYRIGHT
=========

This document is licensed under the same licence as Varnish
itself. See LICENCE for details.

* Copyright (c) 2011 Aurelien Guillaume
