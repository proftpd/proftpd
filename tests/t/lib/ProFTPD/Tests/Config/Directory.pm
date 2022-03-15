package ProFTPD::Tests::Config::Directory;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Data::Dumper;
use File::Path qw(mkpath rmtree);
use File::Spec;
use IO::Handle;
use Time::HiRes qw(gettimeofday tv_interval);

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  dir_wide_layout => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  # dir_deep_layout
  # dir_wide_deep_layout
  #
  # I suspect that, due to the nature of the parser, the order in which
  # the <Directory> sections appear in the config can affect performance.
  # If the _last_ <Directory> section is for the most common path referenced,
  # it could mean longer traversal times (for each lookup) before the
  # match is made.
};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

my $prev_name = undef;
my $prev_namelen = undef;

sub get_name {
  my $name_len = shift;
  my $inc = shift;

  # If the requested name length has changed, start over
  if ($name_len != $prev_namelen) {
    $prev_name = undef;
  }

  if (defined($prev_name)) {
    # Split the name into its individual chars, in reverse order
    my @chars = reverse(split('', $prev_name));

    # Increment the first char, then reassemble the name.  We only want
    # ASCII characters (i.e. A-Za-z inclusive).  So if the incremented first
    # char is outside the range, reset the first char to the range start, and
    # increment the next char.

    for (my $i = 0; $i < $prev_namelen; $i++) {
      my $char = $chars[$i];
      my $val = ord($char);

      $char = chr(++$val);

      my $reset_char = 0;
      while ($char !~ /[A-Za-z]/o) {
        ++$val;
        if ($val > 122) {
          # Too far; reset to 'A'.
          $val = 65;
          $reset_char = 1;
        }

        $char = chr($val);
      }

      $chars[$i] = $char;

      unless ($reset_char) {
        last;
      }
    }

    $prev_name = join('', reverse(@chars));

  } else {
    $prev_name = "A" x $name_len;
    $prev_namelen = $name_len;
  }

  return $prev_name;
}

sub dir_wide_layout {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'dir');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'directory:10',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DefaultChdir => '~',

    Directory => {
      '/' => {
        Umask => '066 077',
      },
    },

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Append our mess of many wide <Directory> sections to the config:
  #
  #  <Directory /path/to/a>
  #    Umask 066 077
  #  </Directory>
  #
  #  <Directory/path/to/b>
  #    Umask 066 077
  #  </Directory>

  my $target_dir;

  if (open(my $fh, ">> $setup->{config_file}")) {
    my $width = 1000;
    my $namelen = 3;

    for (my $i = 0; $i < $width; $i++) {
      $target_dir = get_name($namelen, 1);
      my $dir = File::Spec->rel2abs("$tmpdir/$target_dir");

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# Creating $dir\n";
      }

      mkpath($dir);

      # Make sure that, if we're running as root, that the test dir has
      # permissions/privs set for the account we create
      if ($< == 0) {
        unless (chown($setup->{uid}, $setup->{gid}, $dir)) {
          die("Can't set owner of $dir to $setup->{uid}/$setup->{gid}: $!");
        }
      }

      print $fh <<EOD;
<Directory ~/$target_dir>
  Umask 066 077
</Directory>
EOD
    }

    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # To test the worst-case scenario, the target directory (to which we will
  # write a file) should be the _last_ in the list.

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# target directory: $target_dir\n";
  }

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

      my $start_time = [gettimeofday()];

      my $conn = $client->stor_raw("$target_dir/test.txt");
      unless ($conn) {
        die("Failed to STOR $target_dir/test.txt: " . $client->response_code() .
          " " . $client->response_msg());
      }

      my $elapsed = tv_interval($start_time);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# elapsed: $elapsed\n";
      }

      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
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
