package ProFTPD::Tests::Modules::mod_load;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Carp;
use Cwd;
use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use IO::Socket::INET;
use POSIX qw(:fcntl_h);
use Time::HiRes qw(gettimeofday tv_interval usleep);

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  load_login_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  load_too_high => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  load_too_high_custom_response => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  load_var_current_load => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  load_var_max_load => {
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

sub load_login_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'load');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'load:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_load.c' => {
        MaxLoad => '10',
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

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 10);
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
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /\<load:9\>: current system load = \S+, max load = \S+/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected TraceLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub load_too_high {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'load');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'load:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_load.c' => {
        MaxLoad => '0.01',
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

      eval { ProFTPD::TestSuite::FTP->new('127.0.0.1', $port) };
      unless ($@) {
        die("Connect succeeded unexpectedly");
      }

      my $ex = ProFTPD::TestSuite::FTP::get_connect_exception();
      my $expected = "System busy, try again later";
      $self->assert($expected eq $ex,
        test_msg("Expected '$expected', got '$ex'"));
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

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /\<load:9\>: current system load = \S+, max load = \S+/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected TraceLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub load_too_high_custom_response {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'load');

  my $busy_msg = "I'm busy, go away!";

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'load:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_load.c' => {
        MaxLoad => "0.01 \"$busy_msg\"",
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

      eval { ProFTPD::TestSuite::FTP->new('127.0.0.1', $port) };
      unless ($@) {
        die("Connect succeeded unexpectedly");
      }

      my $ex = ProFTPD::TestSuite::FTP::get_connect_exception();
      my $expected = $busy_msg;
      $self->assert($expected eq $ex,
        test_msg("Expected '$expected', got '$ex'"));
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

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /\<load:9\>: current system load = \S+, max load = \S+/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected TraceLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub load_var_current_load {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'load');

  my $display_connect = File::Spec->rel2abs("$tmpdir/display-connect.txt");
  if (open(my $fh, "> $display_connect")) {
    print $fh "Current load: %{mod_load.curr_load}\n";

    unless (close($fh)) {
      die("Can't write $display_connect: $!");
    }

  } else {
    die("Can't open $display_connect: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'display:20 load:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DisplayConnect => $display_connect,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_load.c' => {
        MaxLoad => '10',
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

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0);
      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg(0);

      my $expected = 220;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Current load: \S+';
      $self->assert(qr/$expected/, $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

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
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /\<load:9\>: current system load = \S+, max load = \S+/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected TraceLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub load_var_max_load {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'load');

  my $max_load = '9.15';

  my $display_connect = File::Spec->rel2abs("$tmpdir/display-connect.txt");
  if (open(my $fh, "> $display_connect")) {
    print $fh "Max load: %{mod_load.max_load}\n";

    unless (close($fh)) {
      die("Can't write $display_connect: $!");
    }

  } else {
    die("Can't open $display_connect: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'display:20 load:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DisplayConnect => $display_connect,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_load.c' => {
        MaxLoad => $max_load,
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

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0);
      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg(0);

      my $expected = 220;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Max load: (\S+)';
      $self->assert(qr/$expected/, $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $resp_msg =~ /$expected/;
      $self->assert($1 eq $max_load,
        test_msg("Expected '$max_load', got '$1'"));

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
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /\<load:9\>: current system load = \S+, max load = \S+/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected TraceLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

1;
