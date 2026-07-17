package ProFTPD::Tests::Modules::mod_wrap;

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
  wrap_access_files => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  wrap_user_access_files => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  wrap_group_access_files => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  wrap_service_name => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  wrap_access_files_bug3332 => {
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

sub wrap_access_files {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'wrap');

  my $allow_file = File::Spec->rel2abs("$tmpdir/wrap.allow");
  if (open(my $fh, "> $allow_file")) {
    print $fh "proftpd: ALL\n";

    unless (close($fh)) {
      die("Can't write $allow_file: $!");
    }

  } else {
    die("Can't open $allow_file: $!");
  }

  my $deny_file = File::Spec->rel2abs("$tmpdir/wrap.deny");
  if (open(my $fh, "> $deny_file")) {
    print $fh "ALL: ALL\n";

    unless (close($fh)) {
      die("Can't write $deny_file: $!");
    }

  } else {
    die("Can't open $deny_file: $!");
  }

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

      'mod_wrap.c' => {
        TCPAccessFiles => "$allow_file $deny_file",
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

      my ($resp_code, $resp_msg) = $client->login($setup->{user}, $setup->{passwd});

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

  test_cleanup($setup, $ex);
}

sub wrap_user_access_files {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'wrap');

  my $allow_file = File::Spec->rel2abs("$tmpdir/wrap.allow");
  if (open(my $fh, "> $allow_file")) {
    print $fh "proftpd: ALL\n";

    unless (close($fh)) {
      die("Can't write $allow_file: $!");
    }

  } else {
    die("Can't open $allow_file: $!");
  }

  my $deny_file = File::Spec->rel2abs("$tmpdir/wrap.deny");
  if (open(my $fh, "> $deny_file")) {
    print $fh "ALL: ALL\n";

    unless (close($fh)) {
      die("Can't write $deny_file: $!");
    }

  } else {
    die("Can't open $deny_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'regexp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_wrap.c' => {
        TCPUserAccessFiles => "$setup->{user} $allow_file $deny_file",
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
      my ($resp_code, $resp_msg) = $client->login($setup->{user}, $setup->{passwd});

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

  test_cleanup($setup, $ex);
}

sub wrap_group_access_files {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'wrap');

  my $allow_file = File::Spec->rel2abs("$tmpdir/wrap.allow");
  if (open(my $fh, "> $allow_file")) {
    print $fh "proftpd: ALL\n";

    unless (close($fh)) {
      die("Can't write $allow_file: $!");
    }

  } else {
    die("Can't open $allow_file: $!");
  }

  my $deny_file = File::Spec->rel2abs("$tmpdir/wrap.deny");
  if (open(my $fh, "> $deny_file")) {
    print $fh "ALL: ALL\n";

    unless (close($fh)) {
      die("Can't write $deny_file: $!");
    }

  } else {
    die("Can't open $deny_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'regexp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_wrap.c' => {
        TCPGroupAccessFiles => "$setup->{group} $allow_file $deny_file",
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
      my ($resp_code, $resp_msg) = $client->login($setup->{user}, $setup->{passwd});

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

  test_cleanup($setup, $ex);
}

sub wrap_service_name {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'wrap');

  my $service = 'foobar';

  my $allow_file = File::Spec->rel2abs("$tmpdir/wrap.allow");
  if (open(my $fh, "> $allow_file")) {
    print $fh "$service: ALL\n";

    unless (close($fh)) {
      die("Can't write $allow_file: $!");
    }

  } else {
    die("Can't open $allow_file: $!");
  }

  my $deny_file = File::Spec->rel2abs("$tmpdir/wrap.deny");
  if (open(my $fh, "> $deny_file")) {
    print $fh "ALL: ALL\n";

    unless (close($fh)) {
      die("Can't write $deny_file: $!");
    }

  } else {
    die("Can't open $deny_file: $!");
  }

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

      'mod_wrap.c' => {
        TCPUserAccessFiles => "$setup->{user} $allow_file $deny_file",
        TCPServiceName => $service,
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
      my ($resp_code, $resp_msg) = $client->login($setup->{user}, $setup->{passwd});

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

  test_cleanup($setup, $ex);
}

sub wrap_access_files_bug3332 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'wrap');

=pod
  my $fh;
  my $allow_file = File::Spec->rel2abs("$tmpdir/wrap.allow");
  if (open($fh, "> $allow_file")) {
    print $fh "proftpd: ALL\n";

    unless (close($fh)) {
      die("Can't write $allow_file: $!");
    }

  } else {
    die("Can't open $allow_file: $!");
  }

  my $deny_file = File::Spec->rel2abs("$tmpdir/wrap.deny");
  if (open($fh, "> $deny_file")) {
    print $fh "ALL: ALL\n";

    unless (close($fh)) {
      die("Can't write $deny_file: $!");
    }

  } else {
    die("Can't open $deny_file: $!");
  }
=cut

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

      'mod_wrap.c' => {
        TCPAccessFiles => "~/wrap.allow ~/wrap.deny",
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

      eval { $client->login('anonymous', 'ftp@nospam.org') };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 530;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Login incorrect.";
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

  test_cleanup($setup, $ex);
}

1;
