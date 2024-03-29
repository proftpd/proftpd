package ProFTPD::Tests::Modules::mod_delay;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use Time::HiRes qw(gettimeofday tv_interval);

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  delay_cold_table => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  delay_warm_table => {
    order => ++$order,
    test_class => [qw(forking slow)],
  },

  delay_extra_user_cmd_bug3622 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  delay_extra_pass_cmd_bug3622 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  delay_table_none_bug4020 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  delay_delayonevent_user_bug4020 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  delay_delayonevent_pass_bug4020 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  delay_delayonevent_failedlogin_bug4020 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  delay_delayonevent_user_pass_bug4020 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  delay_table_default_issue1440 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  delay_delayonevent_connect_issue1701 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub delay_cold_table {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'delay');

  my $delay_tab = File::Spec->rel2abs("$setup->{home_dir}/delay.tab");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'delay:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayTable => $delay_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub delay_warm_table {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'delay');

  my $delay_tab = File::Spec->rel2abs("$setup->{home_dir}/delay.tab");

  # In order to warm up the DelayTable, we need to fill its columns,
  # which means more than 256 logins before the table is "warm".
  my $nlogins = 300;

  my $timeout = ($nlogins * 2);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'delay:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayTable => $delay_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $max_elapsed = -1;

      for (my $i = 0; $i < $nlogins; $i++) {
        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

        my $start = [gettimeofday()];
        $client->login($setup->{user}, $setup->{passwd});
        my $elapsed = tv_interval($start);

        $client->quit();

        if ($elapsed > $max_elapsed) {
          $max_elapsed = $elapsed;
        }

        if ($ENV{TEST_VERBOSE}) {
          if ($i % 50 == 0) {
            print STDERR " + login #", $i + 1, " (max elapsed = $max_elapsed)\n";
          }
        }
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR " + max elapsed = $max_elapsed\n";
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, $timeout) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub delay_extra_user_cmd_bug3622 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'delay');

  my $delay_tab = File::Spec->rel2abs("$tmpdir/delay.tab");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'delay:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayTable => $delay_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      # Note that, with Bug#4217, a second USER command will succeed.
      eval { $client->user($setup->{user}) };
      if ($@) {
        die("USER failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 230;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "User $setup->{user} logged in";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex) if $ex;

  # Examine the TraceLog, looking for "unable to load DelayTable" messages.
  # There shouldn't be any.

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 1;
      my $expected = '\[\d+\]\s+<(\S+):(\d+)>: (.*?)$';

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /$expected/) {
          my $trace_channel = $1;
          my $trace_level = $2;
          my $trace_msg = $3;

          next unless $trace_channel eq 'delay';

          if ($trace_msg =~ /unable to load DelayTable/) {
            $ok = 0;
            last;
          }
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Trace messages appeared unexpectedly"));

    } else {
      die("Can't open $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub delay_extra_pass_cmd_bug3622 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'delay');

  my $delay_tab = File::Spec->rel2abs("$setup->{home_dir}/delay.tab");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'delay:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayTable => $delay_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      eval { $client->pass($setup->{passwd}) };
      unless ($@) {
        die("Second PASS command succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 503;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'You are already logged in';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex) if $ex;

  # Examine the TraceLog, looking for "unable to load DelayTable" messages.
  # There shouldn't be any.

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 1;

      while (my $line = <$fh>) {
        chomp($line);

        my $expected = '\[\d+\]\s+<(\S+):(\d+)>: (.*?)$';

        if ($line =~ /$expected/) {
          my $trace_channel = $1;
          my $trace_level = $2;
          my $trace_msg = $3;

          next unless $trace_channel eq 'delay';

          if ($trace_msg =~ /unable to load DelayTable/) {
            $ok = 0;
            last;
          }
        }
      }

      close($fh);

      $self->assert($ok, test_msg("Trace messages appeared unexpectedly"));

    } else {
      die("Can't open $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub delay_table_none_bug4020 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'delay');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'delay:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayTable => 'none',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex) if $ex;

  # Examine the TraceLog, looking for "unable to load DelayTable" messages.
  # There shouldn't be any.

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 1;

      while (my $line = <$fh>) {
        chomp($line);

        my $expected = '\[\d+\]\s+<(\S+):(\d+)>: (.*?)$';

        if ($line =~ /$expected/) {
          my $trace_channel = $1;
          my $trace_level = $2;
          my $trace_msg = $3;

          next unless $trace_channel eq 'delay';

          if ($trace_msg =~ /(unable to load|error opening) DelayTable/) {
            $ok = 0;

            if ($ENV{TEST_VERBOSE}) {
              print STDERR " + unexpected TraceLog line: $line\n";
            }

            last;
          }
        }
      }

      close($fh);

      $self->assert($ok, test_msg("Trace messages appeared unexpectedly"));

    } else {
      die("Can't open $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub delay_delayonevent_user_bug4020 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'delay');

  my $user_delay_secs = 2;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'delay:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayTable => 'none',
        DelayOnEvent => 'USER 2000ms',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0,
        $user_delay_secs + 2);

      my $start = [gettimeofday()];
      $client->login($setup->{user}, $setup->{passwd});
      my $elapsed = tv_interval($start);

      $client->quit();

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Elapsed login time: $elapsed secs\n";
      }

      if ($elapsed < $user_delay_secs) {
        die("Expected at least $user_delay_secs sec delay, got $elapsed");
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub delay_delayonevent_pass_bug4020 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'delay');

  my $pass_delay_secs = 2;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'delay:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayTable => 'none',
        DelayOnEvent => 'PASS 2000',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0,
        $pass_delay_secs + 2);

      my $start = [gettimeofday()];
      eval { $client->login($setup->{user}, 'foobar') };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }
      my $elapsed = tv_interval($start);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Elapsed login time: $elapsed secs\n";
      }

      if ($elapsed < $pass_delay_secs) {
        die("Expected at least $pass_delay_secs sec delay, got $elapsed");
      }

      $start = [gettimeofday()];
      $client->login($setup->{user}, $setup->{passwd});
      $elapsed = tv_interval($start);

      $client->quit();

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Elapsed login time: $elapsed secs\n";
      }

      if ($elapsed < $pass_delay_secs) {
        die("Expected at least $pass_delay_secs sec delay, got $elapsed");
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub delay_delayonevent_failedlogin_bug4020 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'delay');

  my $failed_delay_secs = 2;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'delay:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayTable => 'none',
        DelayOnEvent => 'FailedLogin 2000',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0,
        $failed_delay_secs + 2);

      my $start = [gettimeofday()];
      eval { $client->login($setup->{user}, 'foobar') };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }
      my $elapsed = tv_interval($start);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Elapsed login time: $elapsed secs\n";
      }

      if ($elapsed < $failed_delay_secs) {
        die("Expected at least $failed_delay_secs sec delay, got $elapsed");
      }

      $start = [gettimeofday()];
      $client->login($setup->{user}, $setup->{passwd});
      $elapsed = tv_interval($start);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Elapsed login time: $elapsed secs\n";
      }

      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub delay_delayonevent_user_pass_bug4020 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'delay');

  my $login_delay_secs = 4;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'delay:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => [
        'DelayTable none',
        'DelayOnEvent USER 2sec',
        'DelayOnEvent PASS 2sec',
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0,
        $login_delay_secs + 2);

      my $start = [gettimeofday()];
      $client->login($setup->{user}, $setup->{passwd});
      my $elapsed = tv_interval($start);

      $client->quit();

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Elapsed login time: $elapsed secs\n";
      }

      if ($elapsed < $login_delay_secs) {
        die("Expected at least $login_delay_secs sec delay, got $elapsed");
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub delay_table_default_issue1440 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'delay');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'delay:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        'DelayEngine on',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 2);

      my $start = [gettimeofday()];
      $client->login($setup->{user}, $setup->{passwd});
      my $elapsed = tv_interval($start);

      $client->quit();

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Elapsed login time: $elapsed secs\n";
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

# mod_delay/0.7: no DelayOnEvent rules configured with "DelayTable none" in effect, disabling module

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $saw_delaytable_none = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /.*?DelayTable none.*?in effect, disabling module/) {
          $saw_delaytable_none = 1;
          last;
        }
      }

      close($fh);

      $self->assert($saw_delaytable_none == 0,
        test_msg("Saw 'DelayTable none' in effect unexpectedly"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub delay_delayonevent_connect_issue1701 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'delay');

  my $pass_delay_secs = 2;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'delay:20 event:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayTable => 'none',
        DelayOnEvent => 'Connect 100-5000ms',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      for (my $i = 0; $i < 10; $i++) {
        my $start = [gettimeofday()];
        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 10);
        my $elapsed = tv_interval($start);

        $client->login($setup->{user}, $setup->{passwd});

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Elapsed connect time: $elapsed secs\n";
        }

        $client->quit();
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 300) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

1;
