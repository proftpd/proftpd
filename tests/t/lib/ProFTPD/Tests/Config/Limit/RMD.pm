package ProFTPD::Tests::Config::Limit::RMD;

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
  rmd_unremovable_subdir => {
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

sub rmd_unremovable_subdir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'limit');

  my $test_dir = File::Spec->rel2abs("$tmpdir/domain.com/web");
  mkpath($test_dir);

  my $sub_dir = File::Spec->rel2abs("$tmpdir/domain.com/web/special");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the test directories have
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $test_dir, $sub_dir)) {
      die("Can't set perms on $test_dir, $sub_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $test_dir, $sub_dir)) {
      die("Can't set owner of $test_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }
 
  if ($^O eq 'darwin') {
    # Mac OSX hack
    $sub_dir = '/private' . $sub_dir;
  }
 
  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'command:10 directory:10',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DefaultChdir => '~',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },

  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<Directory />
  <Limit ALL SITE_CHMOD>
    DenyAll
  </Limit>

  <Limit DIRS>
    AllowAll
  </Limit>
</Directory>

<Directory /*/domain.com/web>
  <Limit ALL>
    AllowAll
  </Limit>

  <Limit RMD XRMD>
    DenyFilter special(/)?\$
  </Limit>
</Directory>

<Directory /*/domain.com/web/special/*>
  <Limit RMD XRMD>
    AllowAll
  </Limit>
</Directory>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      # We should be able to create and delete a directory under web/.
      # We should be able to create and delete a directory under web/special/.
      # We should NOT be able to delete the web/special/ directory.

      my ($resp_code, $resp_msg) = $client->mkd('domain.com/web/foo');

      my $expected = 257;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "\"$setup->{home_dir}/domain.com/web/foo\" - Directory successfully created";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      ($resp_code, $resp_msg) = $client->rmd('domain.com/web/foo');

      $expected = 250;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "RMD command successful";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      ($resp_code, $resp_msg) = $client->mkd('domain.com/web/special/foo');

      $expected = 257;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "\"$setup->{home_dir}/domain.com/web/special/foo\" - Directory successfully created";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      ($resp_code, $resp_msg) = $client->rmd('domain.com/web/special/foo');

      $expected = 250;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "RMD command successful";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      eval { $client->rmd('domain.com/web/special') };
      unless ($@) {
        die("RMD domain.com/web/special succeeded unexpectedly");
      }

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "domain.com/web/special: Permission denied";
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

  test_cleanup($setup->{log_file}, $ex);
}

1;
