/*-
 * Copyright (c) 2010-2011 Varnish Software AS
 * All rights reserved.
 *
 * Author: Aurelien Guillaume <aurelien@iwi.me>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcre.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"
#include "md5.h"

const char * __match_proto__()
vmod_check_url(struct sess *sp, struct vmod_priv *priv, const char *url,
			   const char *secret, const char *expired_url, const char *error_url)
{
	unsigned int url_length;
	int result;
#define VECSZ 40
	int vec[VECSZ];

	unsigned u;
	char *b, *e;
	const char *ptr;

	md5_state_t ctx;
	md5_byte_t  dig[16];
	char        dig_str[32];
	unsigned    dig_pos;

	long long   hash_time_scan;
	unsigned int hash_prefix_len;
	unsigned int hash_prefix_len_force;
	struct timeval tv;
	

	if (!url || !secret)
	{
    	WSP(sp, SLT_VCL_Log, "vmod_secdown: No URL given, or no secret.");  
		return (error_url);
	}

	url_length = strlen(url);

	// Check minimal valid URL len:  /<1..>/<32>/<8>, 44 bytes
	// This is for performance reasons - no use to preg_match a URL
	// that will not match anyways.
	if (url_length < 44)
	{
    	WSP(sp, SLT_VCL_Log, "vmod_secdown: URL too short: %u bytes.", url_length);  
		return (error_url);
	}

	// Check session validity
	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC); 

	// Match it.
	result = pcre_exec(
		(pcre *)priv->priv, /* result of pcre_compile() */
        NULL,           /* we didn't study the pattern */
        url,            /* the subject string */
        url_length,     /* the length of the subject string */
        0,              /* start at offset 0 in the subject */
        0,              /* default options */
        vec,            /* vector of integers for substring information */
        VECSZ);         /* number of elements (NOT size in bytes) */

	if (result != 4 && result != 5 /* 3 matches plus the global match, and eventually
									the prefix len match */)
	{
    	WSP(sp, SLT_VCL_Log, "vmod_secdown: URL did not match the secdown scheme. Components matched: %d", result);  
		return (error_url);
	}

	// By default, hash_prefix_len = URL length
	hash_prefix_len = vec[3] - vec[2];

	// If we have a prefix len match, convert it.
	if (result == 5)
	{
		// Convert the prefix len from the URL
		if (sscanf(url + vec[8], "x%x", &hash_prefix_len_force) != 1)
		{
			WSP(sp, SLT_VCL_Log, "vmod_secdown: cannot parse hash_prefix variable.");
			return (error_url);
		}

		// If the prefix len is shorter than the URL, use the prefix len.
		if (hash_prefix_len_force < hash_prefix_len)
			hash_prefix_len = hash_prefix_len_force;
	}

	// Validate the MD5 hash: url/secret/hextime
	md5_init(&ctx);
	// Stage 1: the url, that may be shortened to hash_prefix_len
	md5_append(&ctx, url + vec[2], hash_prefix_len);
	// Add a /
	md5_append(&ctx, "/", 1);
	// Stage 2: the secret
	md5_append(&ctx, secret, strlen(secret));
	// Stage 3: Hex time, plus preceding /
	md5_append(&ctx, url + vec[6] - 1, vec[7] + 1 /* / */ - vec[6]);

	// If we have a prefix len match, it's also part of the hash string
	//  - the preceding "x" is included.
	if (result == 5)
		md5_append(&ctx, url + vec[8], vec[9] - vec[8]);

	md5_finish(&ctx, dig);

	for (dig_pos = 0; dig_pos < 16; ++dig_pos)
		sprintf(dig_str + dig_pos * 2, "%02x", dig[dig_pos]);


	if (strncmp(dig_str, url + vec[4] /* Hash in the URL */, 32))
	{
    	WSP(sp, SLT_VCL_Log, "vmod_secdown: invalid hash - hash: %s, hash_prefix_len: %d, url_length: %d", dig_str, hash_prefix_len, vec[3] - vec[2]);  
		return (error_url);
	}

	// The URL is now definitely valid. We should just check if the
	// timestamp is still in the acceptable range.
	
	// Convert the timestamp from the URL
	if (sscanf(url + vec[6], "%llx", &hash_time_scan) != 1)
	{
    	WSP(sp, SLT_VCL_Log, "vmod_secdown: could not match the hash timestamp.");  
		return (error_url);
	}

	// Compare the time to the request time.
	if (sp->t_req > (double)hash_time_scan)
	{
    	WSP(sp, SLT_VCL_Log, "vmod_secdown: valid, but expired hash");  
		return (expired_url);
	}
	
	// The download is authorized, we'll return the original URL, but we need to
	// duplicate it to the WS, as we cannot hijack the original one with "\0".

	// Allocate some space from the sessions' WS.
	u = WS_Reserve(sp->wrk->ws, 0);
	e = b = sp->wrk->ws->f;
	e += u;

	// Copy the target URL (first match) in the WS.
	for (ptr = (url + vec[2]); b < e && (ptr < (url + vec[3])) && *url != '\0'; ptr++)
		*b++ = (*ptr);

	// Terminate the string if we have space allocated.
	if (b < e)
		*b = '\0';
	b++;
	
	if (b > e) {
		// We used more than what was available, bail out.
		WS_Release(sp->wrk->ws, 0);
    	WSP(sp, SLT_VCL_Log, "vmod_secdown: allocation error");  
		return (error_url);
	}

	// Update the WS with the space allocated, and release it.
	e = b;
	b = sp->wrk->ws->f;
	WS_Release(sp->wrk->ws, e - b);
	
	// The real URL is now in the WS, ready to be read.
	return (b);
}

void
free_secdown(void *secdown)
{
	pcre_free((pcre *)secdown);	
}


int
init_function(struct vmod_priv *priv, const struct VCL_conf *cfg)
{
	(void)cfg;

	pcre *re;
	const char *error;
	int erroffset;
	re = pcre_compile(
           "^(.*)/([0-9a-f]{32})/([0-9a-f]{8})(x[0-9a-f]{4})?$", /* the pattern */
           0,                /* default options */
           &error,           /* for error message */
           &erroffset,       /* for error offset */
           NULL);            /* use default character tables */

	if (!re)
		// Failed !?
		return (1);

	priv->priv = (void *)re;
	priv->free = free_secdown;
	return (0);
}


