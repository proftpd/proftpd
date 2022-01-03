package ProFTPD::Tests::Commands::HELP;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :features :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  help_ok => {
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

sub help_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $auth_helps = [
    ' NOOP    FEAT    OPTS    HOST    CLNT    AUTH*   CCC*    CONF*   ',
    ' ENC*    MIC*    PBSZ*   PROT*   TYPE    STRU    MODE    RETR    ',
    ' STOR    STOU    APPE    REST    ABOR    RANG    USER    PASS    ',
  ];

  my $expected_nhelp = 9;

  my $have_digest = feature_have_module_compiled('mod_digest.c');
  if ($have_digest) {
    # For the following commands added by mod_digest: HASH, MD5, XCRC, XMD5,
    #  XSHA, XSHA1, XSHA256, and XSHA512.
    $expected_nhelp += 1;
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

      $client->help();
      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();

      my $expected = 214;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# HELP:\n";
        for (my $i = 0; $i < scalar(@$resp_msgs); $i++) {
          print STDERR "#  $resp_msgs->[$i]\n";
        }
      }

      my $nhelp = scalar(@$resp_msgs);
      $self->assert($expected_nhelp == $nhelp,
        test_msg("Expected nrows $expected, got $nhelp"));

      my $helps = [(
        'The following commands are recognized (* =>\'s unimplemented):',
        ' CWD     XCWD    CDUP    XCUP    SMNT*   QUIT    PORT    PASV    ',
        ' EPRT    EPSV    ALLO    RNFR    RNTO    DELE    MDTM    RMD     ',
        ' XRMD    MKD     XMKD    PWD     XPWD    SIZE    SYST    HELP    ',
        @$auth_helps,
        ' ACCT*   REIN*   LIST    NLST    STAT    SITE    MLSD    MLST    ',
      )];

      if ($have_digest) {
        push(@$helps, ' HASH    XCRC    MD5     XMD5    XSHA    XSHA1   XSHA256 XSHA512 ');
      }

      push(@$helps, 'Direct comments to root@127.0.0.1');

      for (my $i = 0; $i < $nhelp; $i++) {
        $expected = $helps->[$i];
        $self->assert($expected eq $resp_msgs->[$i],
          test_msg("Expected '$expected', got '$resp_msgs->[$i]'"));
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

  test_cleanup($setup->{log_file}, $ex);
}

1;
