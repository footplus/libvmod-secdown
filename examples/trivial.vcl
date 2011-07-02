#
# A trivial example of how to use vmod_secdown to protect a particular directory
# See generate-hash.sh to get yourself a valid download link.
# 
# E.g.:
# # ./generate-hash.sh h4ackm3 /protected/1024.rnd 30
#  -> Expires in 30 secs, 1309636072 -> 1309636102.
#  -> Expiry time is 4e0f7606.
#  -> Hash string is /protected/1024.rnd/h4ackm3/4e0f7606
#  -> Hash is 90e4c5513880d97e3a83cb5cd3a20bbd
# The full protected file path is: /protected/1024.rnd/90e4c5513880d97e3a83cb5cd3a20bbd/4e0f7606
# 
# You can enter in your browser, to access your file:
# http://<cache_url>/protected/1024.rnd/90e4c5513880d97e3a83cb5cd3a20bbd/4e0f7606 
#

import secdown;

backend default {
     .host = "127.0.0.1";
	 .port = "8080";
}

sub vcl_recv {
	# Apply only to files in /protected on the backend.
	if (req.url ~ "^/protected/") {
		set req.url = secdown.check_url(req.url, "h4ckm3", "/expired.html", "/error.html");
	}
}

