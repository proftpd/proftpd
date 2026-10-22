package ProFTPD::Tests::Modules::mod_facl;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  facl_bug4303 => {
    order => ++$order,
    test_class => [qw(forking os_linux)],
  },

  facl_group_deny_list_hidenoaccess_issue2389 => {
    order => ++$order,
    test_class => [qw(bug forking os_linux)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub facl_bug4303 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'facl');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/sub.d");
  mkpath($sub_dir);

  if ($< == 0) {
    unless (chown($setup->{uid}, $setup->{gid}, $sub_dir)) {
      die("Can't set owner of $sub_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  # Follow the reproduction recipe in Bug#4303.
  my $cmd = "tail -n1 /etc/passwd | cut -d: -f1";
  my $output = `$cmd`;
  chomp($output);
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Results for command: $cmd: '$output'\n";
  }
  my $acl_user = $output;

  $cmd = "setfacl -m u:$acl_user:rwx $sub_dir 2>&1";
  $output = [`$cmd`];
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Results for command: $cmd:\n";
    print STDERR join('', @$output), "\n";
  }

  $cmd = "setfacl -m g::rx $sub_dir 2>&1";
  $output = [`$cmd`];
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Results for command: $cmd:\n";
    print STDERR join('', @$output), "\n";
  }

  $cmd = "setfacl -m g:$acl_user:rwx $sub_dir 2>&1";
  $output = [`$cmd`];
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Results for command: $cmd:\n";
    print STDERR join('', @$output), "\n";
  }

  $cmd = "setfacl -m m::rwx $sub_dir 2>&1";
  $output = [`$cmd`];
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Results for command: $cmd:\n";
    print STDERR join('', @$output), "\n";
  }

  $cmd = "getfacl --access $sub_dir | setfacl -d -M- $sub_dir 2>&1";
  $output = [`$cmd`];
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Results for command: $cmd:\n";
    print STDERR join('', @$output), "\n";
  }

  $cmd = "getfacl $sub_dir 2>&1";
  $output = [`$cmd`];
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Results for command: $cmd:\n";
    print STDERR join('', @$output), "\n";
  }

  my $test_dir = File::Spec->rel2abs("$tmpdir/sub.d/test.d");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'fsio:20 facl:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

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
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 2);
      $client->login($setup->{user}, $setup->{passwd});
      $client->mkd('sub.d/test.d');
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

  $cmd = "getfacl $test_dir 2>&1";
  $output = [`$cmd`];
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Results for command: $cmd:\n";
    print STDERR join('', @$output), "\n";
  }

  my $seen = grep(/^mask::rwx$/, @$output);
  $self->assert($seen == 1,
    "Expected 'mask::rwx' not appearing in getfacl results");

  test_cleanup($setup, $ex);
}

sub facl_group_deny_list_hidenoaccess_issue2389 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'facl');

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  # Ensure that the test user does not have access.
  my $cmd = "setfacl -m u:1:rwx $test_file 2>&1";
  my $output = [`$cmd`];
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Results for command: $cmd:\n";
    print STDERR join('', @$output), "\n";
  }

  # Ensure that the test group does not have access.
  $cmd = "setfacl -m g:1:rx $test_file 2>&1";
  $output = [`$cmd`];
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Results for command: $cmd:\n";
    print STDERR join('', @$output), "\n";
  }

  $cmd = "setfacl -m g:$setup->{gid}:--- $test_file 2>&1";
  $output = [`$cmd`];
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Results for command: $cmd:\n";
    print STDERR join('', @$output), "\n";
  }

  $cmd = "getfacl $test_file 2>&1";
  $output = [`$cmd`];
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Results for command: $cmd:\n";
    print STDERR join('', @$output), "\n";
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'fsio:20 facl:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },

    Directory => {
      '/' => {
        HideNoAccess => 'on',
      },
    }
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
      # Allow for server startup
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 2);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->list_raw('-l *.txt');
      unless ($conn) {
        die("LIST failed unexpected: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 25);
      sleep(0.25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# data: $buf";
      }

      $client->quit();

      # We have to be careful of the fact that readdir returns directory
      # entries in an unordered fashion.
      my $res = {};
      my $lines = [split(/\n/, $buf)];
      foreach my $line (@$lines) {
        if ($line =~ /^\S+\s+\d+\s+\S+\s+\S+\s+.*?\s+(\S+)$/) {
          $res->{$1} = 1;
        }
      }

      my $expected = {
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
        die("Unexpected name '$mismatch' appeared in LIST data")
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

1;
