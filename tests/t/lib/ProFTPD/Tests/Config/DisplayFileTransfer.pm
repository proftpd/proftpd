package ProFTPD::Tests::Config::DisplayFileTransfer;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  displayfilexfer_abs_path => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  displayfilexfer_rel_path => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  displayfilexfer_chrooted => {
    order => ++$order,
    test_class => [qw(forking rootprivs)],
  },

  displayfilexfer_multiline => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  displayfilexfer_non_path => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  # XXX Add other tests with the various Display variables
};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

# Support routines

sub read_conn {
  my $conn = shift;

  my $buf = '';
  my $tmp;
  while ($conn->read($tmp, 8192, 10)) {
    $buf .= $tmp;
  }
}

# Test cases

sub displayfilexfer_abs_path {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'config');

  my $xfer_file = File::Spec->rel2abs("$tmpdir/xfer.txt");
  if (open(my $fh, "> $xfer_file")) {
    print $fh "Hello user!\n";

    unless (close($fh)) {
      die("Unable to write $xfer_file: $!");
    }

    # Make sure that, if we're running as root, that the test file has
    # permissions/privs set for the account we create
    if ($< == 0) {
      unless (chown($setup->{uid}, $setup->{gid}, $xfer_file)) {
        die("Can't set owner of $xfer_file to $setup->{uid}/$setup->{gid}: $!");
      }
    }

  } else {
    die("Unable to open $xfer_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DisplayFileTransfer => $xfer_file,

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
      # Allow server to start up
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->retr_raw('config.conf');
      unless ($conn) {
        die("RETR config.conf failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      read_conn($conn);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();

      my $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Hello user!";
      $self->assert($expected eq $resp_msgs->[0],
        test_msg("Expected response message '$expected', got '$resp_msgs->[0]'"));

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

sub displayfilexfer_rel_path {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'config');

  my $xfer_file = 'xfer.txt';

  my $xfer_path = File::Spec->rel2abs("$tmpdir/$xfer_file");
  if (open(my $fh, "> $xfer_path")) {
    print $fh "Hello user!\n";

    unless (close($fh)) {
      die("Unable to write $xfer_path: $!");
    }

    # Make sure that, if we're running as root, that the test file has
    # permissions/privs set for the account we create
    if ($< == 0) {
      unless (chown($setup->{uid}, $setup->{gid}, $xfer_path)) {
        die("Can't set owner of $xfer_path to $setup->{uid}/$setup->{gid}: $!");
      }
    }

  } else {
    die("Unable to open $xfer_path: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DisplayFileTransfer => $xfer_file,

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
      # Allow server to start up
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->retr_raw('config.conf');
      unless ($conn) {
        die("RETR config.conf failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      read_conn($conn);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();

      my $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Hello user!";
      $self->assert($expected eq $resp_msgs->[0],
        test_msg("Expected response message '$expected', got '$resp_msgs->[0]'"));

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

sub displayfilexfer_chrooted {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'config');

  my $xfer_file = File::Spec->rel2abs("$tmpdir/xfer.txt");
  if (open(my $fh, "> $xfer_file")) {
    print $fh "Hello user!\n";
    unless (close($fh)) {
      die("Can't write $xfer_file: $!");
    }

    # Make sure that, if we're running as root, that the test file has
    # permissions/privs set for the account we create
    if ($< == 0) {
      unless (chown($setup->{uid}, $setup->{gid}, $xfer_file)) {
        die("Can't set owner of $xfer_file to $setup->{uid}/$setup->{gid}: $!");
      }
    }

  } else {
    die("Can't open $xfer_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$setup->{home_dir}/test.txt");
  if (open(my $fh, "> $test_file")) {
    close($fh);

    # Make sure that, if we're running as root, that the test file has
    # permissions/privs set for the account we create
    if ($< == 0) {
      unless (chown($setup->{uid}, $setup->{gid}, $test_file)) {
        die("Can't set owner of $test_file to $setup->{uid}/$setup->{gid}: $!");
      }
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DefaultRoot => '~',
    DisplayFileTransfer => $xfer_file,

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
      # Allow server to start up
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->retr_raw('test.txt');
      unless ($conn) {
        die("RETR test.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      read_conn($conn);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();

      my $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Hello user!";
      $self->assert($expected eq $resp_msgs->[0],
        test_msg("Expected response message '$expected', got '$resp_msgs->[0]'"));

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

sub displayfilexfer_multiline {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'config');

  my $xfer_file = File::Spec->rel2abs("$tmpdir/xfer.txt");
  if (open(my $fh, "> $xfer_file")) {
    print $fh "Thanks for transferring a file\nEnjoy the bits\nHello user!\n";

    unless (close($fh)) {
      die("Unable to write $xfer_file: $!");
    }

    # Make sure that, if we're running as root, that the test file has
    # permissions/privs set for the account we create
    if ($< == 0) {
      unless (chown($setup->{uid}, $setup->{gid}, $xfer_file)) {
        die("Can't set owner of $xfer_file to $setup->{uid}/$setup->{gid}: $!");
      }
    }

  } else {
    die("Unable to open $xfer_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DisplayFileTransfer => $xfer_file,

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
      # Allow server to start up
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->retr_raw('config.conf');
      unless ($conn) {
        die("RETR config.conf failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      read_conn($conn);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();

      my $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = " Hello user!";
      $self->assert($expected eq $resp_msgs->[2],
        test_msg("Expected response message '$expected', got '$resp_msgs->[2]'"));

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

sub displayfilexfer_non_path {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'config');

  my $xfer_file = '"SUCCESS: Transfer file count:%t | Bytes transferred:%K"';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'response:10',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DisplayFileTransfer => $xfer_file,

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->retr_raw('config.conf');
      unless ($conn) {
        die("RETR config.conf failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 32768, 5);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));
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

1;
