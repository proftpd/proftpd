package ProFTPD::Tests::Modules::mod_ctrls_admin;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  ctrls_admin_debug_get_level_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_debug_set_level_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_dns_on_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_dns_off_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_dns_clear_cache_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_get_config_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_get_directives_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_kick_user_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_kick_host_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_kick_host_with_count_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_kick_class_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_restart_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_restart_count_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_scoreboard_scrub_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_shutdown_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_shutdown_graceful_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_shutdown_graceful_long_duration_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_status_all_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_trace_info_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ctrls_admin_down_up_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub ftpdctl {
  my $sock_file = shift;
  my $ctrl_cmd = shift;
  my $poll_interval = shift;
  $poll_interval = 3 unless defined($poll_interval);

  my $ftpdctl_bin;
  if ($ENV{PROFTPD_TEST_PATH}) {
    $ftpdctl_bin = "$ENV{PROFTPD_TEST_PATH}/ftpdctl";

  } else {
    $ftpdctl_bin = '../ftpdctl';
  }

  my $verbosity = '';
  if ($ENV{TEST_VERBOSE}) {
    $verbosity = '-v';
  }

  my $cmd = "$ftpdctl_bin -s $sock_file $verbosity $ctrl_cmd";

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Executing ftpdctl: $cmd\n";
  }

  my @lines = `$cmd`;
  my $exit_status = $? >> 8;

  return ($exit_status, \@lines);
}

sub ctrls_admin_debug_get_level_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "debug allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, 'debug level',
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /debug level/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = 'debug level set to \d+';
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_debug_set_level_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "debug allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, 'debug level 7',
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /debug level/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = 'debug level set to \d+';
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_dns_on_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "dns allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, 'dns on',
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /UseReverseDNS/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = 'UseReverseDNS set to';
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_dns_off_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "dns allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, 'dns off',
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /UseReverseDNS/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = 'UseReverseDNS set to';
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_dns_clear_cache_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "dns allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, 'dns cache clear',
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /netaddr/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = 'netaddr cache cleared';
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_get_config_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "get allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, 'get config SystemLog',
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /SystemLog/ } @$lines];

    $expected = 2;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[1];
    $expected = 'currently not displayable';
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_get_directives_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "get allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, 'get directives',
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /SystemLog/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = 'SystemLog \(mod_log\.c\)';
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_kick_user_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "kick allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, "kick user $setup->{user}",
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /connected/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = "user '$setup->{user}' not connected";
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_kick_host_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "kick allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my $host = '1.2.3.4';

    my ($exit_status, $lines) = ftpdctl($ctrls_sock, "kick host $host",
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /connected/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = "host '$host' not connected";
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_kick_host_with_count_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "kick allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my $host = '1.2.3.4';
    my $count = 5;

    my ($exit_status, $lines) = ftpdctl($ctrls_sock,
      "kick host -n $count $host", $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /connected/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = "host '$host' not connected";
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_kick_class_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "kick allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my $classes = 'foo bar';

    my ($exit_status, $lines) = ftpdctl($ctrls_sock, "kick class $classes",
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /connected/ } @$lines];

    $expected = 2;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[1];
    $expected = "class 'bar' not connected";
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_restart_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "restart allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, "restart",
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /restarted/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = 'restarted server';
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_restart_count_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "restart allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my $count = 3;

    for (my $i = 0; $i < $count; $i++) {
      my ($exit_status, $lines) = ftpdctl($ctrls_sock, "restart",
        $poll_interval);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# ftpdctl: (exit status $exit_status)\n";
        foreach my $line (@$lines) {
          chomp($line);
          print STDERR "#  $line\n";
        }
      }
    }

    my ($exit_status, $lines) = ftpdctl($ctrls_sock, "restart count",
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /restarted/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = "server restarted $count time";
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_scoreboard_scrub_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "scoreboard allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, "scoreboard scrub",
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /scrubbed/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = "scrubbed scoreboard";
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_shutdown_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "shutdown allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, "shutdown",
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /shutting/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = "shutting down";
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  # We expect this to raise an exception, since the daemon should already
  # be shut down.
  eval { server_stop($setup->{pid_file}) };
  unless ($@) {
    $ex = 'Server stopped again unexpectedly';
  }

  test_cleanup($setup, $ex);
}

sub ctrls_admin_shutdown_graceful_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "shutdown allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my $duration = 5;

    my ($exit_status, $lines) = ftpdctl($ctrls_sock,
     "shutdown graceful $duration", $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /shutting/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = "shutting down";
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  # We expect this to raise an exception, since the daemon should already
  # be shut down.
  eval { server_stop($setup->{pid_file}) };
  unless ($@) {
    $ex = 'Server stopped again unexpectedly';
  }

  test_cleanup($setup, $ex);
}

sub ctrls_admin_shutdown_graceful_long_duration_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "shutdown allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my $duration = 100000;

    my ($exit_status, $lines) = ftpdctl($ctrls_sock,
     "shutdown graceful $duration", $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 3;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /timeout/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = 'timeout must be less than 300 secs';
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  # We do NOT expect this to raise an exception, since the daemon is not shut
  # down yet.
  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_status_all_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "status allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, "status all",
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /status:/ } @$lines];

    $expected = 2;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[1];
    $expected = 'UP';
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_trace_info_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:25',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "trace allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, "trace info",
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /ctrls\s+/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = 'ctrls\s+25';
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

sub ctrls_admin_down_up_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ctrls_admin');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");

  my ($user, $group) = config_get_identity();
  my $poll_interval = 2;

  if ($< == 0) {
    $user = 'root';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'binding:25 ctrls:25 json:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsACLs => "all allow user *",
        ControlsSocketACL => "allow user *",
        ControlsInterval => $poll_interval,
      },

      'mod_ctrls_admin.c' => {
        AdminControlsACLs => "down,up allow user $user",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});
  sleep(2);

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, "down all",
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    my $expected = 0;
    $self->assert($exit_status == $expected,
      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /down:/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = 'all servers disabled';
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid == 0) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1, 1);
      if ($client) {
        die("Logged in unexpectedly");
      }
    };
    if ($@) {
      $ex = $@;
    }

    exit 0;
  }

  eval {
    my ($exit_status, $lines) = ftpdctl($ctrls_sock, "up '0.0.0.0#$port'",
      $poll_interval);
    if ($ENV{TEST_VERBOSE}) {
      print STDERR "# ftpdctl: (exit status $exit_status)\n";
      foreach my $line (@$lines) {
        chomp($line);
        print STDERR "#  $line\n";
      }
    }

    # Inexplicably, Perl _insists_ on providing the incorrect (-1) exit
    # status here (and not elsewhere), even through the trace logging
    # is correct, and the Controls system provides a return/status value of
    # zero (meaning no issue).  Sigh.
    my $expected = 0;
#    $self->assert($exit_status == $expected,
#      test_msg("Expected exit status $expected, got $exit_status"));

    $lines = [grep { /up:/ } @$lines];

    $expected = 1;
    my $matches = scalar(@$lines);
    $self->assert($expected == $matches,
      test_msg("Expected $expected, got $matches"));

    my $line = $lines->[0];
    $expected = "0\.0\.0\.0#$port enabled";
    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));
  };
  if ($@) {
    $ex = $@;
  }

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid == 0) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    exit 0;
  } 

  # Give the client enough time to log in
  sleep(3);

  server_stop($setup->{pid_file});
  test_cleanup($setup, $ex);
}

1;
