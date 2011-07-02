/*
 *
 * NB:  This file is machine generated, DO NOT EDIT!
 *
 * Edit vmod.vcc and run vmod.py instead
 */

#include "vrt.h"
#include "vcc_if.h"


typedef const char * td_secdown_check_url(struct sess *, struct vmod_priv *, const char *, const char *, const char *, const char *);
typedef const char * td_secdown_author(struct sess *, const char *);

const char Vmod_Name[] = "secdown";
const struct Vmod_Func_secdown {
	td_secdown_check_url	*check_url;
	td_secdown_author	*author;
	vmod_init_f	*_init;
} Vmod_Func = {
	vmod_check_url,
	vmod_author,
	init_function,
};

const int Vmod_Len = sizeof(Vmod_Func);

const char Vmod_Proto[] =
	"typedef const char * td_secdown_check_url(struct sess *, struct vmod_priv *, const char *, const char *, const char *, const char *);\n"
	"typedef const char * td_secdown_author(struct sess *, const char *);\n"
	"\n"
	"struct Vmod_Func_secdown {\n"
	"	td_secdown_check_url	*check_url;\n"
	"	td_secdown_author	*author;\n"
	"	vmod_init_f	*_init;\n"
	"} Vmod_Func_secdown;\n"
	;

const char * const Vmod_Spec[] = {
	"secdown.check_url\0Vmod_Func_secdown.check_url\0STRING\0PRIV_VCL\0STRING\0STRING\0STRING\0STRING\0",
	"secdown.author\0Vmod_Func_secdown.author\0STRING\0ENUM\0footy\0\0",
	"INIT\0Vmod_Func_secdown._init",
	0
};

