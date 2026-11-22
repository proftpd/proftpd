package ProFTPD::Tests::Modules::mod_procfs::digest;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Cwd;
use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use IPC::Open3;
use Socket;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  procfs_digest_hash => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_digest_md5 => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_digest_xmd5 => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_digest_xcrc => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_digest_xsha => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_digest_xsha1 => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_digest_xsha256 => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_digest_xsha512 => {
    order => ++$order,
    test_class => [qw(forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
#    procfs_digest_xsha
#    procfs_digest_xsha1
#    procfs_digest_xsha256
}

sub procfs_digest_hash {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 digest:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_digest.c' => {
        DigestEngine => 'on',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
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

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $algo = 'CRC32';
      my ($resp_code, $resp_msg) = $client->opts('HASH', $algo);

      my $expected = 200;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = $algo;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      eval { $client->quote('HASH', $test_file) };
      unless ($@) {
        die("HASH command succeeded unexpectedly");
      }

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$test_file: No such file or directory";
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /HASH $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_digest_md5 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 digest:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_digest.c' => {
        DigestEngine => 'on',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
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

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      eval { $client->quote('MD5', $test_file) };
      unless ($@) {
        die("MD5 command succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$test_file: No such file or directory";
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /MD5 $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_digest_xmd5 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 digest:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_digest.c' => {
        DigestEngine => 'on',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
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

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      eval { $client->quote('XMD5', $test_file) };
      unless ($@) {
        die("XMD5 command succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$test_file: No such file or directory";
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /XMD5 $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_digest_xcrc {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 digest:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_digest.c' => {
        DigestEngine => 'on',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
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

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      eval { $client->quote('XCRC', $test_file) };
      unless ($@) {
        die("XCRC command succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$test_file: No such file or directory";
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /XCRC $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_digest_xsha {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 digest:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_digest.c' => {
        DigestEngine => 'on',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
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

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      eval { $client->quote('XSHA', $test_file) };
      unless ($@) {
        die("XSHA command succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$test_file: No such file or directory";
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /XSHA $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_digest_xsha1 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 digest:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_digest.c' => {
        DigestEngine => 'on',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
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

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      eval { $client->quote('XSHA1', $test_file) };
      unless ($@) {
        die("XSHA1 command succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$test_file: No such file or directory";
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /XSHA1 $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_digest_xsha256 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 digest:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_digest.c' => {
        DigestEngine => 'on',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
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

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      eval { $client->quote('XSHA256', $test_file) };
      unless ($@) {
        die("XSHA256 command succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$test_file: No such file or directory";
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /XSHA256 $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_digest_xsha512 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 digest:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_digest.c' => {
        DigestEngine => 'on',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
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

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      eval { $client->quote('XSHA512', $test_file) };
      unless ($@) {
        die("XSHA512 command succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$test_file: No such file or directory";
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /XSHA512 $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

1;
