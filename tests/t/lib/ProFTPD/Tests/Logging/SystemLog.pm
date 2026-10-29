package ProFTPD::Tests::Logging::SystemLog;

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
  systemlog_default => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  systemlog_with_sysloglevel_crit => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  systemlog_with_debuglevel => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  systemlog_ifclass_matching_class_bug3832 => {
    order => ++$order,
    test_class => [qw(bug forking mod_ifsession)],
  },

  systemlog_ifclass_not_matching_class_bug3832 => {
    order => ++$order,
    test_class => [qw(bug forking mod_ifsession)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub systemlog_default {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'systemlog');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    # Default SyslogLevel is now "notice", and our desired message is logged
    # at "info".  Ah well.
    SyslogLevel => 'info',

    TransferLog => 'none',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {

      # We should see the following, in the order defined:
      #
      #  "FTP session opened"
      #  "USER proftpd: Login successful."
      #  "FTP session closed"

      my $saw_opened = 0;
      my $saw_login = 0;
      my $saw_closed = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if (!$saw_opened) {
          if ($line =~ /FTP session opened/) {
            $saw_opened = 1;
          }

        } else {
          if (!$saw_login) {
            if ($line =~ /USER $setup->{user}: Login successful/) {
              $saw_login = 1;
            }

          } else {
            if (!$saw_closed) {
              if ($line =~ /FTP session closed/) {
                $saw_closed = 1;
                last;
              }
            }
          }
        }
      }

      close($fh);

      $self->assert($saw_opened, test_msg("Expected 'FTP session opened' message not seen"));
      $self->assert($saw_login, test_msg("Expected 'USER $setup->{user}: Login successful' message not seen"));
      $self->assert($saw_closed, test_msg("Expected 'FTP session closed' message not seen"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub systemlog_with_sysloglevel_crit {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'systemlog');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SyslogLevel => 'crit',
    TransferLog => 'none',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {

      # We should NOT see any of the following, due to the SyslogLevel
      # filtering:
      #
      #  "FTP session opened"
      #  "USER proftpd: Login successful."
      #  "FTP session closed"

      my $saw_opened = 0;
      my $saw_login = 0;
      my $saw_closed = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /FTP session opened/) {
          $saw_opened = 1;
        }

        if (!$saw_login) {
          if ($line =~ /USER $setup->{user}: Login successful/) {
            $saw_login = 1;
          }
        }

        if (!$saw_closed) {
          if ($line =~ /FTP session closed/) {
            $saw_closed = 1;
          }
        }
      }

      close($fh);

      $self->assert(!$saw_opened, test_msg("Unexpectedly saw 'FTP session opened' message"));
      $self->assert(!$saw_login, test_msg("Unexpectedly saw 'USER $setup->{user}: Login successful' message"));
      $self->assert(!$saw_closed, test_msg("Unexpectedly saw 'FTP session closed' message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub systemlog_with_debuglevel {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'systemlog');

  my $timeout_session = 60;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DebugLevel => 4,

    # Use this to trigger a debug level 4 log message
    TimeoutSession => $timeout_session,
    TransferLog => 'none',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {

      # With a TimeoutSession set, and DebugLevel set to 4, we should see:
      #
      #  "setting TimeoutSession of 60 seconds"

      my $saw_mesg = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /setting TimeoutSession of $timeout_session seconds/) {
          $saw_mesg = 1;
          last;
        }
      }

      close($fh);
      $self->assert($saw_mesg, test_msg("Did not see 'setting TimeoutSession of $timeout_session seconds' message as expected"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub systemlog_ifclass_matching_class_bug3832 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'systemlog');

  my $system_log = File::Spec->rel2abs("$tmpdir/system.log");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{system_log},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<Class local>
  From 127.0.0.1
</Class>

<IfClass local>
  SystemLog none
</IfClass>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

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
      $client->type('ascii');

      my $test_file = 'systemlog.conf';
      my $conn = $client->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 25);
      eval { $conn->close() };
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

  eval {
    if (open(my $fh, "< $system_log")) {
      my $sess_nlines = 0;
      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /session (opened|closed)/) {
          $sess_nlines++;
        }
      }

      close($fh);
      $self->assert($sess_nlines == 0,
        test_msg("Expected no lines in $system_log, got $sess_nlines lines"));

    } else {
      die("Can't read $system_log: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub systemlog_ifclass_not_matching_class_bug3832 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'systemlog');

  my $system_log = File::Spec->rel2abs("$tmpdir/system.log");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{system_log},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<Class local>
  From 127.0.0.1
</Class>

<IfClass !local>
  SystemLog none
</IfClass>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

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
      $client->type('ascii');

      my $test_file = 'systemlog.conf';
      my $conn = $client->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 25);
      eval { $conn->close() };
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

  eval {
    if (open(my $fh, "< $system_log")) {
      my $sess_nlines = 0;
      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /session (opened|closed)/) {
          $sess_nlines++;
        }
      }

      close($fh);
      $self->assert($sess_nlines > 0,
        test_msg("Expected lines in $system_log, got none"));

    } else {
      die("Can't read $system_log: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

1;
