package ProFTPD::Tests::Modules::mod_log_forensic;

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
  forensic_failed_login => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  forensic_good_login => {
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

sub forensic_failed_login {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'forensic');

  my $forensic_log_file = File::Spec->rel2abs("$tmpdir/forensic.log");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_log_forensic.c' => {
        ForensicLogEngine => 'on',
        ForensicLogCriteria => 'FailedLogin',
        ForensicLogFile => $forensic_log_file,
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
      eval { $client->login($setup->{user}, 'foo') };
      unless ($@) {
        die("Login succeeded unexpectedly");
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

  eval {
    if (open(my $fh, "< $forensic_log_file")) {
      my $begin_ok = 0;
      my $end_ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($line =~ /^\-\-\-\-\-BEGIN FAILED LOGIN FORENSICS\-\-\-\-\-/) {
          $begin_ok = 1;
          next;
        }

        if ($begin_ok and
            $line =~ /^\-\-\-\-\-END FAILED LOGIN FORENSICS\-\-\-\-\-/) {
          $end_ok = 1;
          last;
        }
      }

      close($fh);

      $self->assert($begin_ok and $end_ok,
        test_msg("Expected ForensicLogFile lines did not appear"));

    } else {
      die("Can't open $forensic_log_file: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub forensic_good_login {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'forensic');

  my $forensic_log_file = File::Spec->rel2abs("$tmpdir/forensic.log");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_log_forensic.c' => {
        ForensicLogEngine => 'on',
        ForensicLogCriteria => 'FailedLogin',
        ForensicLogFile => $forensic_log_file,
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
    $self->assert(-z $forensic_log_file,
      test_msg("ForensicLogFile $forensic_log_file unexpectedly not empty"));
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

1;
