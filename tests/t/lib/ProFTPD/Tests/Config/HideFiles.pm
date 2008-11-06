package ProFTPD::Tests::Config::HideFiles;

use lib qw(t/lib);
use base qw(Test::Unit::TestCase ProFTPD::TestSuite::Child);
use strict;

use File::Path qw(mkpath rmtree);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  hidefiles_bug3130 => {
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

sub set_up {
  my $self = shift;

  # Create temporary scratch dir
  eval { mkpath('tmp') };
  if ($@) {
    my $abs_path = File::Spec->rel2abs('tmp');
    die("Can't create dir $abs_path: $@");
  }
}

sub tear_down {
  my $self = shift;
  undef $self;

  # Remove temporary scratch dir
  eval { rmtree('tmp') };
};

sub hidefiles_bug3130 {
  my $self = shift;

  my $config_file = 'tmp/config.conf';
  my $pid_file = File::Spec->rel2abs('tmp/config.pid');
  my $scoreboard_file = File::Spec->rel2abs('tmp/config.scoreboard');
  my $log_file = File::Spec->rel2abs('config.log');

  my $auth_user_file = File::Spec->rel2abs('tmp/config.passwd');
  my $auth_group_file = File::Spec->rel2abs('tmp/config.group');

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs('tmp');

  my $sub_dir = File::Spec->rel2abs('tmp/foo');
  mkpath($sub_dir);

  my $test_file = "X12foo";
  my $fh;
  if (open($fh, "> $sub_dir/$test_file")) {
    close($fh);

  } else {
    die("Can't write test file $sub_dir/$test_file: $!");
  }

  if (open($fh, "> $sub_dir/.in.$test_file")) {
    close($fh);

  } else {
    die("Can't write test file $sub_dir/.in.$test_file: $!");
  }

  auth_user_write($auth_user_file, $user, $passwd, 500, 500, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', 500, $user);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },

    Directory => {
      "$home_dir/*" => {
        HideFiles => '^\.in\.',
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

      # Bug#3130 was happening because of a bad pointer assignment in
      # src/dirtree.c:dir_hide_file().
      #
      # This test should succeed, and NOT show the .in. file.

      my $conn = $client->nlst_raw("foo/*");
      unless ($conn) {
        die("Failed to NLST: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192);
      $conn->close();

      # We have to be careful of the fact that readdir returns directory
      # entries in an unordered fashion.
      my $res = {};
      my $lines = [split(/\n/, $buf)];
      foreach my $line (@$lines) {
        $res->{$line} = 1;
      }

      my $expected = {
        "foo/./$test_file" => 1,
        'foo/../config.conf' => 1,
        'foo/../config.group' => 1,
        'foo/../config.passwd' => 1,
        'foo/../config.pid' => 1,
        'foo/../config.scoreboard' => 1,
        'foo/../foo' => 1,
        "foo/$test_file" => 1,
      };

      my $ok = 1;
      my $mismatch;
      foreach my $name (keys(%$res)) {
        unless (defined($expected->{$name})) {
          $mismatch = $name;
          $ok = 0;
          last;
        }
      }

      unless ($ok) {
        die("Unexpected name '$mismatch' appeared in NLST data")
      }

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, 2) };
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
    die($ex);
  }

  unlink($log_file);
}

1;
