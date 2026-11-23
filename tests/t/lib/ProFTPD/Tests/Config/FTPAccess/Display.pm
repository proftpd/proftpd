package ProFTPD::Tests::Config::FTPAccess::Display;

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
  dirfakeuser_env_var_issue2490 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  dirfakegroup_env_var_issue2490 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  maxtransferperhost_env_var_issue2490 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  maxtransferperuser_env_var_issue2490 => {
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

sub dirfakeuser_env_var_issue2490 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ftpaccess');

  # The .ftpaccess file should contain:
  #
  #    DirFakeUser on %{env:FOO_TEST}
  #
  # If we see the value of that FOO_TEST environment variable in a directory
  # listing, that's the bug.

  my $env_key = 'FOO_TEST';
  my $env_val = 'BAR_BAZ';

  my $ftpaccess_file = File::Spec->rel2abs("$tmpdir/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh <<EOL;
DirFakeUser on %{env:$env_key}
EOL

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    AllowOverride => 'on',
    SetEnv => "$env_key $env_val",

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

      my $conn = $client->list_raw('-l');
      unless ($conn) {
        die("LIST failed: " . $client->response_code() .
          " " . $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 30);
      sleep(0.25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $client->quit();

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# data:\n$buf";
      }

      $self->assert_transfer_ok($resp_code, $resp_msg);

      # We have to be careful of the fact that readdir returns directory
      # entries in an unordered fashion.
      my $res = {};
      my $lines = [split(/\r?\n/, $buf)];
      foreach my $line (@$lines) {
        if ($line =~ /^\S+\s+\d+\s+(\S+)\s+\S+\s+.*?\s+(\S+)$/) {
          $res->{$2} = $1;
        }
      }

      my $expected = {
        'ftpaccess.conf' => $setup->{user},
        'ftpaccess.group' => $setup->{user},
        'ftpaccess.passwd' => $setup->{user},
        'ftpaccess.pid' => $setup->{user},
        'ftpaccess.scoreboard' => $setup->{user},
        'ftpaccess.scoreboard.lck' => $setup->{user},
      };

      my $ok = 1;
      my $mismatch;
      foreach my $name (keys(%$res)) {
        unless (defined($expected->{$name})) {
          $mismatch = $name;
          $ok = 0;
          last;
        }

        if ($res->{$name} ne $setup->{user}) {
          $mismatch = $name;
          $ok = 0;
          last;
        }
      }

      unless ($ok) {
        die("Unexpected name/owner '$mismatch: $res->{$mismatch}' appeared in LIST data")
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

  test_cleanup($setup, $ex);
}

sub dirfakegroup_env_var_issue2490 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ftpaccess');

  # The .ftpaccess file should contain:
  #
  #    DirFakeGroup on %{env:FOO_TEST}
  #
  # If we see the value of that FOO_TEST environment variable in a directory
  # listing, that's the bug.

  my $env_key = 'FOO_TEST';
  my $env_val = 'BAR_BAZ';

  my $ftpaccess_file = File::Spec->rel2abs("$tmpdir/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh <<EOL;
DirFakeGroup on %{env:$env_key}
EOL

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    AllowOverride => 'on',
    SetEnv => "$env_key $env_val",

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

      my $conn = $client->list_raw('-l');
      unless ($conn) {
        die("LIST failed: " . $client->response_code() .
          " " . $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 30);
      sleep(0.25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $client->quit();

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# data:\n$buf";
      }

      $self->assert_transfer_ok($resp_code, $resp_msg);

      # We have to be careful of the fact that readdir returns directory
      # entries in an unordered fashion.
      my $res = {};
      my $lines = [split(/\r?\n/, $buf)];
      foreach my $line (@$lines) {
        if ($line =~ /^\S+\s+\d+\s+\S+\s+(\S+)\s+.*?\s+(\S+)$/) {
          $res->{$2} = $1;
        }
      }

      my $expected = {
        'ftpaccess.conf' => $setup->{group},
        'ftpaccess.group' => $setup->{group},
        'ftpaccess.passwd' => $setup->{group},
        'ftpaccess.pid' => $setup->{group},
        'ftpaccess.scoreboard' => $setup->{group},
        'ftpaccess.scoreboard.lck' => $setup->{group},
      };

      my $ok = 1;
      my $mismatch;
      foreach my $name (keys(%$res)) {
        unless (defined($expected->{$name})) {
          $mismatch = $name;
          $ok = 0;
          last;
        }

        if ($res->{$name} ne $setup->{group}) {
          $mismatch = $name;
          $ok = 0;
          last;
        }
      }

      unless ($ok) {
        die("Unexpected name/owner '$mismatch: $res->{$mismatch}' appeared in LIST data")
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

  test_cleanup($setup, $ex);
}

sub maxtransferperhost_env_var_issue2490 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ftpaccess');

  # The .ftpaccess file should contain:
  #
  #    MaxTransfersPerHost RETR 1 %{env:FOO_TEST}
  #
  # If we see the value of that FOO_TEST environment variable in an FTP
  # response, that's the bug.

  my $env_key = 'FOO_TEST';
  my $env_val = 'BAR_BAZ';

  my $ftpaccess_file = File::Spec->rel2abs("$tmpdir/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh <<EOL;
MaxTransfersPerHost RETR 1 %{env:$env_key}
EOL

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
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

    AllowOverride => 'on',
    SetEnv => "$env_key $env_val",

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
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($setup->{user}, $setup->{passwd});

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($setup->{user}, $setup->{passwd});

      my $conn1 = $client1->retr_raw('test.dat');
      unless ($conn1) {
        die("RETR failed: " . $client1->response_code() .
          " " . $client1->response_msg());
      }

      my $conn2 = $client2->retr_raw('test.dat');
      if ($conn2) {
        die("RETR succeeded unexpectedly");
      }

      my $resp_code = $client2->response_code();
      my $resp_msgs = $client2->response_msgs();
      $client2->quit();

      my $expected = 451;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'the maximum number of data transfers';
      $self->assert(qr/$expected/, $resp_msgs->[0],
        test_msg("Expected response message '$expected', got '$resp_msgs->[0]'"));

      my $buf;
      $conn1->read($buf, 8192, 30);
      sleep(0.25);
      eval { $conn1->close() };

      $resp_code = $client1->response_code();
      my $resp_msg = $client1->response_msg();
      $client1->quit();

      $self->assert_transfer_ok($resp_code, $resp_msg);
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

  test_cleanup($setup, $ex);
}

sub maxtransferperuser_env_var_issue2490 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ftpaccess');

  # The .ftpaccess file should contain:
  #
  #    MaxTransfersPerUser RETR 1 %{env:FOO_TEST}
  #
  # If we see the value of that FOO_TEST environment variable in an FTP
  # response, that's the bug.

  my $env_key = 'FOO_TEST';
  my $env_val = 'BAR_BAZ';

  my $ftpaccess_file = File::Spec->rel2abs("$tmpdir/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh <<EOL;
MaxTransfersPerUser RETR 1 %{env:$env_key}
EOL

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
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

    AllowOverride => 'on',
    SetEnv => "$env_key $env_val",

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
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($setup->{user}, $setup->{passwd});

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($setup->{user}, $setup->{passwd});

      my $conn1 = $client1->retr_raw('test.dat');
      unless ($conn1) {
        die("RETR failed: " . $client1->response_code() .
          " " . $client1->response_msg());
      }

      my $conn2 = $client2->retr_raw('test.dat');
      if ($conn2) {
        die("RETR succeeded unexpectedly");
      }

      my $resp_code = $client2->response_code();
      my $resp_msgs = $client2->response_msgs();
      $client2->quit();

      my $expected = 451;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'the maximum number of data transfers';
      $self->assert(qr/$expected/, $resp_msgs->[0],
        test_msg("Expected response message '$expected', got '$resp_msgs->[0]'"));

      my $buf;
      $conn1->read($buf, 8192, 30);
      sleep(0.25);
      eval { $conn1->close() };

      $resp_code = $client1->response_code();
      my $resp_msg = $client1->response_msg();
      $client1->quit();

      $self->assert_transfer_ok($resp_code, $resp_msg);
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

  test_cleanup($setup, $ex);
}

1;
