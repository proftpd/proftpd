#!/usr/bin/env perl

# Copyright (c) 2026 The ProFTPD Project team
# SPDX-License-Identifier: GPL-2.0-only WITH vsftpd-openssl-exception

use lib qw(t/lib);
use strict;

use Test::Unit::HarnessUnit;

$| = 1;

my $r = Test::Unit::HarnessUnit->new();
$r->start("ProFTPD::Tests::Commands::PORT");
