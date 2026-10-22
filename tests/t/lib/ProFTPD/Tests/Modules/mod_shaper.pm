package ProFTPD::Tests::Modules::mod_shaper;

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
  shaper_sighup => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  shaper_queue_dos => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  shaper_queue_noencryptedmessages_issue2391 => {
    order => ++$order,
    test_class => [qw(bug feature_openssl forking)],
  },

  # Enable this once Bug#3928 is fixed
#  shaper_resumed_download_bug3928 => {
#    order => ++$order,
#    test_class => [qw(bug forking)],
#  }

  shaper_sighup_shaperlog_bug4077 => {
    order => ++$order,
    test_class => [qw(bug forking os_linux)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub get_server_pid {
  my $pid_file = shift;

  my $pid;
  if (open(my $fh, "< $pid_file")) {
    $pid = <$fh>;
    chomp($pid);
    close($fh);

  } else {
    croak("Can't read $pid_file: $!");
  }

  return $pid;
}

sub server_open_fds {
  my $pid_file = shift;

  my $pid = get_server_pid($pid_file);

  my $proc_dir = "/proc/$pid/fd";
  if (opendir(my $dirh, $proc_dir)) {
    my $count = 0;

    # Only count entries whose names are numbers
    while (my $dent = readdir($dirh)) {
      if ($dent =~ /^\d+$/) {
        $count++;
      }
    }

    closedir($dirh);
    return $count;

  } else {
    croak("Can't open directory '$proc_dir': $!");
  }
}

sub shaper_sighup {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'shaper');

  my $shaper_tab = File::Spec->rel2abs("$tmpdir/shaper.tab");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_shaper.c' => {
        ShaperEngine => 'on',
        ShaperLog => $setup->{log_file},
        ShaperTable => $shaper_tab,
        ShaperAll => 'downrate 1500 uprate 1500',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # First, start the server.
  server_start($setup->{config_file});

  # Give it a second to start up, then send the SIGHUP signal
  sleep(2);
  server_restart($setup->{pid_file});

  # Finally, stop the server
  server_stop($setup->{pid_file});

  test_cleanup($setup, $ex);
}

sub shaper_queue_dos {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'shaper');

  my $shaper_tab = File::Spec->rel2abs("$tmpdir/shaper.tab");

  my $test_count = 100;
  my $test_timeout = 180;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'shaper:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    MaxInstances => $test_count + 1,
    TimeoutIdle => $test_timeout + 10,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_shaper.c' => {
        ShaperEngine => 'on',
        ShaperLog => $setup->{log_file},
        ShaperTable => $shaper_tab,
        ShaperAll => 'downrate 1500 uprate 1500',
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
      # XXX Test how many connections it takes to fill up the msg queue used
      # by mod_shaper.

      my $clients = [];
      for (my $i = 0; $i < $test_count; $i++) {
        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# Connecting client #", $i+1, "\n";
        }

        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 2);
        $client->login($setup->{user}, $setup->{passwd});
        push(@$clients, $client);
      }

      my $count = 0;
      foreach my $client (@$clients) {
        print STDERR "# Disonnecting client #", $count+1, "\n";
        $client->quit();
        $count++;
      }

      $clients = undef;
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, $test_timeout) };
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
      my $rcvd_ok = 0;
      my $encrypted_ok = 0;
      my $decrypted_ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($rcvd_ok == 0 &&
            $line =~ /received prio \S+, rate \S+ down, \S+ up/) {
          $rcvd_ok = 1;
        }

        if ($encrypted_ok == 0 &&
            $line =~ /encrypted \d+ bytes of message data to \d+ bytes/) {
          $encrypted_ok = 1;
        }

        if ($decrypted_ok == 0 &&
            $line =~ /decrypted \d+ bytes of message data to \d+ bytes/) {
          $decrypted_ok = 1;
        }

        if ($rcvd_ok && $encrypted_ok && $decrypted_ok) {
          last;
        }
      }

      close($fh);
      $self->assert($rcvd_ok, test_msg("Did not see expected ShaperLog message"));
      $self->assert($encrypted_ok, test_msg("Did not see expected encryption trace message"));
      $self->assert($decrypted_ok, test_msg("Did not see expected decryption trace message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub shaper_queue_noencryptedmessages_issue2391 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'shaper');

  my $shaper_tab = File::Spec->rel2abs("$tmpdir/shaper.tab");

  my $test_count = 100;
  my $test_timeout = 180;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'shaper:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    MaxInstances => $test_count + 1,
    TimeoutIdle => $test_timeout + 10,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_shaper.c' => {
        ShaperEngine => 'on',
        ShaperLog => $setup->{log_file},
        ShaperTable => $shaper_tab,
        ShaperAll => 'downrate 1500 uprate 1500',
        ShaperOptions => 'NoEncryptedMessages',
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
      # XXX Test how many connections it takes to fill up the msg queue used
      # by mod_shaper.

      my $clients = [];
      for (my $i = 0; $i < $test_count; $i++) {
        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# Connecting client #", $i+1, "\n";
        }

        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 2);
        $client->login($setup->{user}, $setup->{passwd});
        push(@$clients, $client);
      }

      my $count = 0;
      foreach my $client (@$clients) {
        print STDERR "# Disonnecting client #", $count+1, "\n";
        $client->quit();
        $count++;
      }

      $clients = undef;
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, $test_timeout) };
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
      my $rcvd_ok = 0;
      my $encrypted_seen = 0;
      my $decrypted_seen = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($rcvd_ok == 0 &&
            $line =~ /received prio \S+, rate \S+ down, \S+ up/) {
          $rcvd_ok = 1;
        }

        if ($encrypted_seen == 0 &&
            $line =~ /encrypted \d+ bytes of message data to \d+ bytes/) {
          $encrypted_seen = 1;
        }

        if ($decrypted_seen == 0 &&
            $line =~ /decrypted \d+ bytes of message data to \d+ bytes/) {
          $decrypted_seen = 1;
        }

        if ($rcvd_ok && $encrypted_seen && $decrypted_seen) {
          last;
        }
      }

      close($fh);
      $self->assert($rcvd_ok, test_msg("Did not see expected ShaperLog message"));
      $self->assert(!$encrypted_seen, test_msg("Saw unexpected encryption trace message"));
      $self->assert(!$decrypted_seen, test_msg("Saw unexpected decryption trace message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub shaper_resumed_download_bug3928 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/shaper.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/shaper.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/shaper.scoreboard");

  my $log_file = test_get_logfile();

  my $shaper_tab = File::Spec->rel2abs("$tmpdir/shaper.tab");

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/shaper.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/shaper.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");
  if (open(my $fh, "> $test_file")) {
    print $fh 'AbCd' x 8192;
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $test_timeout = 45;

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    AuthOrder => 'mod_auth_file.c',

    AllowRetrieveRestart => 'on',
    TimeoutIdle => $test_timeout + 10,

    IfModules => {
      'mod_shaper.c' => {
        ShaperEngine => 'on',
        ShaperLog => $log_file,
        ShaperTable => $shaper_tab,
        ShaperAll => 'downrate 1 uprate 1500',
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

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
      $client->login($user, $passwd);
      $client->type('binary');

      # Resume downloading this large file at 8K
      $client->rest(8192);

      my $conn = $client->retr_raw('test.dat');
      unless ($conn) {
        die("RETR test.dat failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my ($buf, $tmp);
      while ($conn->read($tmp, 32768, 15)) {
        $buf .= $tmp;
      }

      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, $test_timeout) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub shaper_sighup_shaperlog_bug4077 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'shaper');

  my $shaper_tab = File::Spec->rel2abs("$tmpdir/shaper.tab");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_shaper.c' => {
        ShaperEngine => 'on',
        ShaperLog => $setup->{log_file},
        ShaperTable => $setup->{shaper_tab},
        ShaperAll => 'downrate 1500 uprate 1500',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # First, start the server.
  server_start($setup->{config_file});

  # Give it a second to start up...
  sleep(2);

  my $orig_nfds = server_open_fds($setup->{pid_file});
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Found $orig_nfds open fds after server startup\n";
  }

  # Now modify the config, removing the ShaperLog...
  delete($config->{IfModules}->{'mod_shaper.c'}->{ShaperLog});

  unlink($setup->{config_file});
  ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # ...send SIGHUP...
  server_restart($setup->{pid_file});
  sleep(2);

  # ...and get the open fd count again (should be 1 less).
  my $restart_nfds = server_open_fds($setup->{pid_file});
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Found $restart_nfds open fds after server restart #1\n";
  }

  # Finally, stop the server
  server_stop($setup->{pid_file});

  my $expected_nfds = $orig_nfds-1;
  $self->assert($expected_nfds == $restart_nfds,
    test_msg("Expected $expected_nfds open fds, found $restart_nfds"));

  test_cleanup($setup, $ex);
}

1;
