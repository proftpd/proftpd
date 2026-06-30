package ProFTPD::Tests::Modules::mod_radius;

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
  radius_auth => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  radius_acct => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  radius_acct_aborted_xfer_bug3278 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  radius_userinfo_var_u => {
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

sub radius_auth {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $radius_user = 'proftpd';
  if ($ENV{RADIUS_USER}) {
    $radius_user = $ENV{RADIUS_USER};
  }

  my $radius_passwd = 'test';
  if ($ENV{RADIUS_PASSWD}) {
    $radius_passwd = $ENV{RADIUS_PASSWD};
  }

  my $radius_server = '127.0.0.1';
  if ($ENV{RADIUS_HOST}) {
    $radius_server = $ENV{RADIUS_HOST};
  }

  my $setup = test_setup($tmpdir, 'radius', $radius_user, $radius_passwd);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'auth:10 radius:20',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_radius.c' => {
        RadiusEngine => 'on',
        RadiusLog => $setup->{log_file},
        RadiusAuthServer => "$radius_server:1812 testing123 5",
        RadiusUserInfo => "$setup->{uid} $setup->{gid} $setup->{home_dir} /bin/bash",
        RadiusGroupInfo => "$setup->{group} $radius_user $setup->{gid}",
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

  # Make sure that radiusd is running before running these tests, e.g.:
  #
  #  sudo /path/to/freeradius-dir/sbin/radiusd -X -f -xx

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $client->quit();

      my $expected = 230;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "User $setup->{user} logged in";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));
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

  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup, $ex);
}

sub radius_acct {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $radius_user = 'proftpd';
  if ($ENV{RADIUS_USER}) {
    $radius_user = $ENV{RADIUS_USER};
  }

  my $radius_passwd = 'test';
  if ($ENV{RADIUS_PASSWD}) {
    $radius_passwd = $ENV{RADIUS_PASSWD};
  }

  my $radius_server = '127.0.0.1';
  if ($ENV{RADIUS_HOST}) {
    $radius_server = $ENV{RADIUS_HOST};
  }

  my $setup = test_setup($tmpdir, 'radius', $radius_user, $radius_passwd);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'auth:10 radius:20',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_radius.c' => {
        RadiusEngine => 'on',
        RadiusLog => $setup->{log_file},
        RadiusAuthServer => "$radius_server:1812 testing123 5",
        RadiusAcctServer => "$radius_server:1813 testing123 5",
        RadiusUserInfo => "$setup->{uid} $setup->{gid} $setup->{home_dir} /bin/bash",
        RadiusGroupInfo => "$setup->{group} $setup->{user} $setup->{gid}",
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

  # Make sure that radiusd is running before running these tests, e.g.:
  #
  #  sudo /path/to/freeradius-dir/sbin/radiusd -X -f -xx

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $client->quit();

      my $expected = 230;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "User $setup->{user} logged in";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));
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

  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup, $ex);
}

sub radius_acct_aborted_xfer_bug3278 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $radius_user = 'proftpd';
  if ($ENV{RADIUS_USER}) {
    $radius_user = $ENV{RADIUS_USER};
  }

  my $radius_passwd = 'test';
  if ($ENV{RADIUS_PASSWD}) {
    $radius_passwd = $ENV{RADIUS_PASSWD};
  }

  my $radius_server = '127.0.0.1';
  if ($ENV{RADIUS_HOST}) {
    $radius_server = $ENV{RADIUS_HOST};
  }

  my $setup = test_setup($tmpdir, 'radius', $radius_user, $radius_passwd);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'auth:10 radius:20',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_radius.c' => {
        RadiusEngine => 'on',
        RadiusLog => $setup->{log_file},
        RadiusAuthServer => "$radius_server:1812 testing123 5",
        RadiusAcctServer => "$radius_server:1813 testing123 5",
        RadiusUserInfo => "$setup->{uid} $setup->{gid} $setup->{home_dir} /bin/bash",
        RadiusGroupInfo => "$setup->{group} $setup->{user} $setup->{gid}",
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

  # Make sure that radiusd is running before running these tests, e.g.:
  #
  #  sudo /path/to/freeradius-dir/sbin/radiusd -X -f -xx

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 230;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "User $setup->{user} logged in";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("Failed to STOR test.txt: " . $client->response_code() . " " .
          $client->response_msg());
      }

      for (my $i = 0; $i < 1000; $i++) {
        my $buf = "ABCD" x 1024;
        $conn->write($buf, length($buf));
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

  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup, $ex);
}

sub radius_userinfo_var_u {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $radius_user = 'proftpd';
  if ($ENV{RADIUS_USER}) {
    $radius_user = $ENV{RADIUS_USER};
  }

  my $radius_passwd = 'test';
  if ($ENV{RADIUS_PASSWD}) {
    $radius_passwd = $ENV{RADIUS_PASSWD};
  }

  my $radius_server = '127.0.0.1';
  if ($ENV{RADIUS_HOST}) {
    $radius_server = $ENV{RADIUS_HOST};
  }

  my $setup = test_setup($tmpdir, 'radius', $radius_user, $radius_passwd);

  # Note: This UID/GID needs to match what's on the filesystem.
  my $uid = 1001;
  my $gid = 1001;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'auth:10 radius:20',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_radius.c' => {
        RadiusEngine => 'on',
        RadiusLog => $setup->{log_file},
        RadiusAuthServer => "$radius_server:1812 testing123 5",
        RadiusUserInfo => "$uid $gid /home/%u /bin/bash",
        RadiusGroupInfo => "$setup->{group} $setup->{user} $gid",
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

  # Make sure that radiusd is running before running these tests, e.g.:
  #
  #  sudo /path/to/freeradius-dir/sbin/radiusd -X -f -xx

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $client->quit();

      my $expected = 230;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "User $setup->{user} logged in";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
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

  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup, $ex);
}

1;
