/*
 * $Id: cap_alloc.c,v 1.1 2003-01-03 02:16:17 jwm Exp $
 *
 * Copyright (c) 1997-8 Andrew G Morgan <morgan@linux.kernel.org>
 *
 * See end of file for Log.
 *
 * This file deals with allocation and deallocation of internal
 * capability sets as specified by POSIX.1e (formerlly, POSIX 6).
 */

#include "libcap.h"

/*
 * This function duplicates an internal capability set (x3) with
 * malloc()'d memory. It is the responsibility of the user to call
 * cap_free() to liberate it.
 */

cap_t cap_dup(cap_t cap_d)
{
    cap_t result;

    if (!good_cap_t(cap_d)) {
	_cap_debug("bad argument");
	errno = EINVAL;
	return NULL;
    }

    result = (cap_t) malloc( sizeof(*cap_d) );
    if (result == NULL) {
	_cap_debug("out of memory");
	errno = ENOMEM;
	return NULL;
    }

    memcpy(result, cap_d, sizeof(*cap_d));

    return result;
}


/*
 * Scrub and then liberate an internal capability set.
 */

int cap_free(cap_t *cap_d_p)
{
    if ( cap_d_p && good_cap_t(*cap_d_p) ) {
	memset(*cap_d_p, 0, sizeof(**cap_d_p));
	free(*cap_d_p);
	*cap_d_p = NULL;

	return 0;
    } else {
	_cap_debug("no capability to liberate");
	errno = EINVAL;
	return -1;
    }
}

/*
 * Obtain a blank set of capabilities
 */

cap_t cap_init(void)
{
    cap_t result = (cap_t) calloc( 1, sizeof(*result) );

    if (result) {
	result->magic = CAP_T_MAGIC;
	result->head.version = _LINUX_CAPABILITY_VERSION;
    } else {
	errno = ENOMEM;
    }
    return result;
}

/*
 * $Log: cap_alloc.c,v $
 * Revision 1.1  2003-01-03 02:16:17  jwm
 *
 * Turning mod_linuxprivs into a core module, mod_cap. This is by no means
 * complete.
 *
 * Revision 1.2  1999/09/07 23:14:19  macgyver
 * Updated capabilities library and model.
 *
 * Revision 1.1.1.1  1999/04/17 22:16:31  morgan
 * release 1.0 of libcap
 *
 * Revision 1.3  1998/05/24 22:54:09  morgan
 * updated for 2.1.104
 *
 * Revision 1.2  1997/04/28 00:57:11  morgan
 * fixes and zefram's patches
 *
 * Revision 1.1  1997/04/21 04:32:52  morgan
 * Initial revision
 *
 */
