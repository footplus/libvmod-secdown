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
#define VECSZ 30
	int vec[VECSZ];

	unsigned u;
	char *b, *e;
	const char *ptr;

	md5_state_t ctx;
	md5_byte_t  dig[16];
	char        dig_str[32];
	unsigned    dig_pos;

	time_t      hash_time;
	struct timeval tv;
	

	if (!url || !secret)
		return (error_url);

	url_length = strlen(url);

	// Check minimal valid URL len:  /<1..>/<32>/<8>, 44 bytes
	if (url_length < 44)
		return (error_url);

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

	if (result != 4 /* 3 matches plus the global match */)
		return (error_url);

	// Validate the MD5 hash: url/secret/hextime
	md5_init(&ctx);
	// Stage 1: the url plus trailing /
	md5_append(&ctx, url + vec[2], vec[3] + 1 /* / */ - vec[2]);
	// Stage 2: the secret
	md5_append(&ctx, secret, strlen(secret));
	// Stage 3: Hex time, plus preceding /
	md5_append(&ctx, url + vec[6] - 1, vec[7] + 1 /* / */ - vec[6]);
	md5_finish(&ctx, dig);

	for (dig_pos = 0; dig_pos < 16; ++dig_pos)
		sprintf(dig_str + dig_pos * 2, "%02x", dig[dig_pos]);


	if (strncmp(dig_str, url + vec[4] /* Hash in the URL */, 32))
	{
    	WSP(sp, SLT_VCL_Log, "vmod_secdown: Invalid hash: Computed hash: %s", dig_str);  
		return (error_url);
	}

	// The URL is now definitely valid. We should just check if the
	// timestamp is still in the acceptable range.
	
	// Convert the timestamp from the URL
	if (sscanf(url + vec[6], "%x", &hash_time) != 1)
		return (error_url);

	// Compare the time to the request time.
	if (sp->t_req > (double)hash_time)
		return (expired_url);
	
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
           "^(.*)/([0-9a-f]{32})/([0-9a-f]{8})$", /* the pattern */
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


const char * __match_proto__()
vmod_author(struct sess *sp, const char *id)
{
	(void)sp;
	if (!strcmp(id, "footy"))
		return ("Aurelien Guillaume");
	WRONG("Illegal VMOD enum");
}

