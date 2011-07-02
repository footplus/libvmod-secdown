/*
 *
 * NB:  This file is machine generated, DO NOT EDIT!
 *
 * Edit vmod.vcc and run vmod.py instead
 */

struct sess;
struct VCL_conf;
struct vmod_priv;

const char * vmod_check_url(struct sess *, struct vmod_priv *, const char *, const char *, const char *, const char *);
const char * vmod_author(struct sess *, const char *);
int init_function(struct vmod_priv *, const struct VCL_conf *);
