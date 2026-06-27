package ProFTPD::Tests::Signals::ABRT;

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
  abrt_daemon_ok => {
    order => ++$order,
    test_class => [qw(bug)],
  },
};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub server_abort {
  my $pid_file = shift;

  my $pid;
  if (open(my $fh, "< $pid_file")) {
    $pid = <$fh>;
    chomp($pid);
    close($fh);

  } else {
    croak("Can't read $pid_file: $!");
  }

  unless (kill('ABRT', $pid)) {
    print STDERR "Error sending SIGABRT to PID $pid: $!\n";
  }
}

sub abrt_daemon_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'signals');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # Start server
  server_start($setup->{config_file});

  # Allow a short interval between startup and shutdown
  sleep(1);

  # Abort the server
  server_abort($setup->{pid_file});

  # Make sure that the pid file has been removed by the server as part of
  # its shutdown procedures.  We need the delay since proftpd handles
  # signals synchronously; it make take a short while for proftpd to
  # process the SIGABRT and shut down all of the way.

  sleep(1);

  eval {
    if (-e $setup->{pid_file}) {
      die("Unclean shutdown: PidFile $setup->{pid_file} still present");
    }

    if (-e $setup->{scoreboard_file}) {
      die("Unclean shutdown: ScoreboardFile $setup->{scoreboard_file} still present");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

1;
