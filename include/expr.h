/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2008 The ProFTPD Project team
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

/* Expression API definition
 * $Id: expr.h,v 1.1 2008-06-05 08:01:39 castaglia Exp $
 */

#ifndef PR_EXPR_H
#define PR_EXPR_H

#include "pool.h"

/* For the different types of expressions: AND, OR, and REGEX. */
#define PR_EXPR_EVAL_AND	0
#define PR_EXPR_EVAL_OR		1
#define PR_EXPR_EVAL_REGEX	2

array_header *pr_expr_create(pool *, int *, char **);
int pr_expr_eval_class_and(char **);
int pr_expr_eval_class_or(char **);
int pr_expr_eval_group_and(char **);
int pr_expr_eval_group_or(char **);
int pr_expr_eval_user_and(char **);
int pr_expr_eval_user_or(char **);

#endif /* PR_EXPR_H */
