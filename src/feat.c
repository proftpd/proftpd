/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2001, 2002, 2003 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/*
 * Feature management code
 * $Id: feat.c,v 1.4 2003-02-12 07:34:57 castaglia Exp $
 */

#include "conf.h"

static pool *feat_pool = NULL;
static array_header *feat_list = NULL;
static unsigned int feati = 0U;

void pr_add_feat(const char *feat) {

  /* If no feature-tracking list has been allocated, create one. */
  if (!feat_pool) {
    feat_pool = make_sub_pool(permanent_pool);
    feat_list = make_array(feat_pool, 0, sizeof(char *));
  }

  /* Make sure that the feature being added isn't already in the list. */
  if (feat_list->nelts > 0) {
    register unsigned int i = 0;
    char **feats = (char **) feat_list->elts;

    for (i = 0; i < feat_list->nelts; i++)
      if (!strcmp(feats[i], feat))
        return;
  }

  *((char **) push_array(feat_list)) = pstrdup(feat_pool, feat);
}

const char *pr_get_feat(void) {
  if (feat_list) {
    feati = 0U;
    return ((const char **) feat_list->elts)[feati++];
  }

  return NULL;
}

const char *pr_get_next_feat(void) {
  if (feat_list && feati < feat_list->nelts)
    return ((const char **) feat_list->elts)[feati++];

  return NULL;
}
