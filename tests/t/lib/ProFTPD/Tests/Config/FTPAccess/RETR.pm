package ProFTPD::Tests::Config::FTPAccess::RETR;

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
  ftpaccess_retr_bug2038 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  ftpaccess_anon_retr_bug2038 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
  },

  ftpaccess_anon_retr_bug2461 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub ftpaccess_retr_bug2038 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ftpaccess');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/foo");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the test dir has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chown($setup->{uid}, $setup->{gid}, $sub_dir)) {
      die("Can't set owner of $sub_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  # Write a .ftpaccess file in the sub dir which denies all access 
  my $ftpaccess_file = File::Spec->rel2abs("$tmpdir/foo/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh <<EOF;
<Limit RETR>
  DenyAll
</Limit>
EOF

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  # Next, write a test file in the sub dir.
  my $test_file = File::Spec->rel2abs("$tmpdir/foo/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";

    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

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

    AllowOverride => 'on',

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
      $client->cwd($sub_dir);

      my $conn = $client->retr_raw("test.txt");
      if ($conn) {
        die("RETR test.txt succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "test.txt: Operation not permitted";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # Now download the file again, only this time using the full path
      $conn = $client->retr_raw($test_file);
      if ($conn) {
        die("RETR $test_file succeeded unexpectedly");
      }

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$test_file: Operation not permitted";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # Now prove that the failures are caused by the .ftpaccess file
      # by deleting that file.
      unlink($ftpaccess_file);

      $client->quit();
      $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->cwd($sub_dir);

      $conn = $client->retr_raw("test.txt");
      unless ($conn) {
        die("Failed to RETR test.txt: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 30);
      eval { $conn->close(5) };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR $test_file: " . $client->response_code() . " " .
          $client->response_msg());
      }

      $conn->read($buf, 8192, 30);
      eval { $conn->close(5) };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
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

  test_cleanup($setup->{log_file}, $ex);
}

sub ftpaccess_anon_retr_bug2038 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ftpaccess');

  my ($config_user, $config_group) = config_get_identity();

  my $anon_dir = File::Spec->rel2abs($tmpdir);

  my $sub_dir = File::Spec->rel2abs("$tmpdir/foo");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the test dir has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chown($setup->{uid}, $setup->{gid}, $sub_dir)) {
      die("Can't set owner of $sub_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  # Write a .ftpaccess file in the sub dir which denies all access 
  my $ftpaccess_file = File::Spec->rel2abs("$tmpdir/foo/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh <<EOF;
<Limit RETR>
  DenyAll
</Limit>
EOF

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  # Next, write a test file in the sub dir.
  my $test_file = File::Spec->rel2abs("$tmpdir/foo/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";

    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

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

  # Make a version of the path that the client would see.
  my $anon_test_file = "/foo/test.txt";

  auth_user_write($setup->{auth_user_file}, $config_user, 'foo',
    $setup->{uid}, $setup->{gid}, '/tmp', '/bin/bash');
  auth_group_write($setup->{auth_group_file}, $config_group, $setup->{gid},
    $config_user);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    AllowOverride => 'on',

    Anonymous => {
      $anon_dir => {
        User => $config_user,
        Group => $config_group,
        UserAlias => "anonymous $config_user",
        RequireValidShell => 'off',
      },
    },

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my $port;
  ($port, $config_user, $config_group) = config_write($setup->{config_file},
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
      $client->login('anonymous', 'ftp@nospam.org');
      $client->cwd("foo");

      my $conn = $client->retr_raw("test.txt");
      if ($conn) {
        die("RETR test.txt succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "test.txt: Operation not permitted";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # Now download the file again, only this time using a full path
      $conn = $client->retr_raw($anon_test_file);
      if ($conn) {
        die("RETR $anon_test_file succeeded unexpectedly");
      }

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$anon_test_file: Operation not permitted";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # Now prove that the failures are caused by the .ftpaccess file
      # by deleting that file.
      unlink($ftpaccess_file);

      $client->quit();
      $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login('anonymous', 'ftp@nospam.org');
      $client->cwd("foo");

      $conn = $client->retr_raw("test.txt");
      unless ($conn) {
        die("Failed to RETR test.txt: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 30);
      eval { $conn->close(5) };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->retr_raw($anon_test_file);
      unless ($conn) {
        die("Failed to RETR $anon_test_file: " . $client->response_code() .
          " " .  $client->response_msg());
      }

      $conn->read($buf, 8192, 30);
      eval { $conn->close(5) };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

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

sub ftpaccess_anon_retr_bug2461 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ftpaccess');

  my ($config_user, $config_group) = config_get_identity();

  my $anon_dir = File::Spec->rel2abs($tmpdir);

  # Write a .ftpaccess file in the sub dir which denies all access 
  my $ftpaccess_file = File::Spec->rel2abs("$tmpdir/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh <<EOF;
<Limit READ>
  Allow from 127.0.0.2
  DenyAll
</Limit>
EOF

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  # Next, write a test file in the anon dir.
  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";

    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

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

  # Make a version of the path that the client would see.
  my $anon_test_file = "/test.txt";

  auth_user_write($setup->{auth_user_file}, $config_user, 'foo',
    $setup->{uid}, $setup->{gid}, '/tmp', '/bin/bash');
  auth_group_write($setup->{auth_group_file}, $config_group, 
    $setup->{gid}, $config_user);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    AllowOverride => 'on',

    Anonymous => {
      $anon_dir => {
        User => $config_user,
        Group => $config_group,
        UserAlias => "anonymous $config_user",
        RequireValidShell => 'off',
      },
    },

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my $port;
  ($port, $config_user, $config_group) = config_write($setup->{config_file},
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
      $client->login('anonymous', 'ftp@nospam.org');

      my $conn = $client->retr_raw("test.txt");
      if ($conn) {
        die("RETR test.txt succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "test.txt: Operation not permitted";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # Now do a directory listing...
      $client->list();

      # ...then try the download again
      $conn = $client->retr_raw("test.txt");
      if ($conn) {
        die("RETR test.txt succeeded unexpectedly");
      }

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "test.txt: Operation not permitted";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # Now prove that the failures are caused by the .ftpaccess file
      # by deleting that file.
      unlink($ftpaccess_file);

      $client->quit();
      $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login('anonymous', 'ftp@nospam.org');

      $conn = $client->retr_raw("test.txt");
      unless ($conn) {
        die("Failed to RETR test.txt: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 30);
      eval { $conn->close(5) };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

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

1;
