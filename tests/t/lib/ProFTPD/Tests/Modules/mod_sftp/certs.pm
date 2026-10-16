package ProFTPD::Tests::Modules::mod_sftp::certs;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Cwd;
use Digest::MD5;
use File::Copy;
use File::Path qw(mkpath rmtree);
use File::Spec;
use IO::Handle;
use IPC::Open3;
use POSIX qw(:fcntl_h);
use Socket;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :features :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  # NOTE: Since OpenSSH no longer supports DSA, we currently don't have a
  # great way to provide integration/regression tests for DSA CA keys or
  # DSA certificates.

  # RSA User CA key tests
  sftp_ext_publickey_rsa_ca_rsa_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_rsa_ca_ecdsa256_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_rsa_ca_ecdsa384_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_rsa_ca_ecdsa521_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_rsa_ca_ed25519_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug feature_sodium forking sftp)],
  },

  # ECDSA256 User CA key tests
  sftp_ext_publickey_ecdsa256_ca_rsa_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_ecdsa256_ca_ecdsa256_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_ecdsa256_ca_ecdsa384_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_ecdsa256_ca_ecdsa521_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_ecdsa256_ca_ed25519_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug feature_sodium forking sftp)],
  },

  # ECDSA384 User CA key tests
  sftp_ext_publickey_ecdsa384_ca_rsa_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_ecdsa384_ca_ecdsa256_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_ecdsa384_ca_ecdsa384_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_ecdsa384_ca_ecdsa521_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_ecdsa384_ca_ed25519_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug feature_sodium forking sftp)],
  },

  # ECDSA521 User CA key tests
  sftp_ext_publickey_ecdsa521_ca_rsa_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_ecdsa521_ca_ecdsa256_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_ecdsa521_ca_ecdsa384_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_ecdsa521_ca_ecdsa521_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_ecdsa521_ca_ed25519_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug feature_sodium forking sftp)],
  },

  # ED25519 User CA key tests
  sftp_ext_publickey_ed25519_ca_rsa_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug feature_sodium forking sftp)],
  },

  sftp_ext_publickey_ed25519_ca_ecdsa256_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug feature_sodium forking sftp)],
  },

  sftp_ext_publickey_ed25519_ca_ecdsa384_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug feature_sodium forking sftp)],
  },

  sftp_ext_publickey_ed25519_ca_ecdsa521_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug feature_sodium forking sftp)],
  },

  sftp_ext_publickey_ed25519_ca_ed25519_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug feature_sodium forking sftp)],
  },

  # User certificate configs/options
  sftp_ext_publickey_config_auth_certificates_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  sftp_ext_publickey_certificate_options_allow_match_principals_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking sftp)],
  },

  # TODO: Same tests as above, but using hostbased authentication.  Note that
  # these require running in a Docker Compose setup, since OpenSSH'
  # command-line hostbased authentication support is restrictive/opinionated
  # for use in this kind of integration testing environment.
  #
  # libssh2's certificate support is only for RSA certs, and even then it
  # is broken; it uses the certificate algorithm name as the request
  # signature name, which is invalid.  Sigh.

  # RSA Host CA key tests
  sftp_ext_hostbased_rsa_ca_rsa_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_rsa_ca_ecdsa256_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_rsa_ca_ecdsa384_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_rsa_ca_ecdsa521_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_rsa_ca_ed25519_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  # ECDSA256 Host CA key tests
  sftp_ext_hostbased_ecdsa256_ca_rsa_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ecdsa256_ca_ecdsa256_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ecdsa256_ca_ecdsa384_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ecdsa256_ca_ecdsa521_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ecdsa256_ca_ed25519_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  # ECDSA384 Host CA key tests
  sftp_ext_hostbased_ecdsa384_ca_rsa_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ecdsa384_ca_ecdsa256_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ecdsa384_ca_ecdsa384_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ecdsa384_ca_ecdsa521_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ecdsa384_ca_ed25519_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  # ECDSA521 Host CA key tests
  sftp_ext_hostbased_ecdsa521_ca_rsa_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ecdsa521_ca_ecdsa256_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ecdsa521_ca_ecdsa384_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ecdsa521_ca_ecdsa521_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ecdsa521_ca_ed25519_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  # ED25519 Host CA key tests
  sftp_ext_hostbased_ed25519_ca_rsa_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ed25519_ca_ecdsa256_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ed25519_ca_ecdsa384_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ed25519_ca_ecdsa521_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_ed25519_ca_ed25519_cert_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_certificate_options_allow_empty_principals_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

  sftp_ext_hostbased_certificate_options_allow_match_principals_issue2357 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress os_linux sftp)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  my @tests = testsuite_get_runnable_tests($TESTS);
  return @tests;
}

sub set_up {
  my $self = shift;
  $self->SUPER::set_up(@_);

  # Make sure that mod_sftp does not complain about permissions on the hostkey
  # files.

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/ssh_host_rsa_key');
  my $dsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/ssh_host_dsa_key');

=pod
  unless (chmod(0400, $rsa_host_key, $dsa_host_key)) {
    die("Can't set perms on $rsa_host_key, $dsa_host_key: $!");
  }
=cut
}

sub sftp_ext_hostbased_ca_cert {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  # When run using Docker Compose to mount the expected certs/keys at the
  # very specific filesystem locations mandated by OpenSSH, these paths will
  # be largely ignored.
  my $rfc4716_ca_keys = shift;
  my $cert = shift;
  my $priv_key = shift;
  my $addl_directives = shift;

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/ssh_host_rsa_key');
  my $dsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/ssh_host_dsa_key');

  my $authorized_ca_keys = File::Spec->rel2abs("$tmpdir/authorized_ca_keys");
  unless (copy($rfc4716_ca_keys, $authorized_ca_keys)) {
    die("Can't copy $rfc4716_ca_keys to $authorized_ca_keys: $!");
  }

  my $batch_file = File::Spec->rel2abs("$tmpdir/sftp-batch.txt");
  if (open(my $fh, "> $batch_file")) {
    print $fh "ls -al\n";

    unless (close($fh)) {
      die("Can't write $batch_file: $!");
    }

  } else {
    die("Can't open $batch_file: $!");
  }

  my $sftp_config = [
    'SFTPEngine on',
    "SFTPLog $setup->{log_file}",
    "SFTPHostKey $rsa_host_key",
    "SFTPHostKey $dsa_host_key",
    "SFTPAuthorizedHostCAKeys file:$authorized_ca_keys",
  ];
  if (defined($addl_directives)) {
    push(@$sftp_config, @$addl_directives);
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ssh2:30 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => $sftp_config,
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

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $sftp = 'sftp';

      my @cmd = (
        $sftp,
        '-oBatchMode=yes',
        '-oCheckHostIP=no',
        '-oCompression=yes',
        "-oPort=$port",
        '-oIdentitiesOnly=yes',
        '-oHostbasedAuthentication=yes',
        '-oEnableSSHKeysign=yes',
        '-oStrictHostKeyChecking=no',
        '-oUpdateHostkeys=no',
        '-oUserKnownHostsFile=/dev/null',
        '-oHostKeyAlgorithms=ssh-rsa',
        '-vvv',
        '-b',
        "$batch_file",
        "$setup->{user}\@127.0.0.1",
      );

      my $sftp_rh = IO::Handle->new();
      my $sftp_wh = IO::Handle->new();
      my $sftp_eh = IO::Handle->new();

      $sftp_wh->autoflush(1);

      sleep(1);

      local $SIG{CHLD} = 'DEFAULT';

      # Make sure that the perms on the cert, key are what OpenSSH wants
      unless (chmod(0400, $cert, $priv_key)) {
        die("Can't set perms on $cert to 0400: $!");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Executing: ", join(' ', @cmd), "\n";
      }

      my $sftp_pid = open3($sftp_wh, $sftp_rh, $sftp_eh, @cmd);
      waitpid($sftp_pid, 0);
      my $exit_status = $?;

      # Restore the perms on the cert, key
      unless (chmod(0644, $cert, $priv_key)) {
        die("Can't set perms on $cert to 0644: $!");
      }

      my ($res, $errstr);
      if ($exit_status >> 8 == 0) {
        $errstr = join('', <$sftp_eh>);
        $res = 0;

      } else {
        $errstr = join('', <$sftp_eh>);
        $res = 1;
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Stderr: $errstr\n";
      }

      unless ($res == 0) {
        die("Can't list files on server: $errstr");
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /EXTENDED_REPLY limits\@openssh.com: .*$/) {
          $ok = 1;
          last;
        }
      }

      close($fh);

      $self->assert($ok,
        test_msg("Did not see expected log message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub sftp_ext_publickey_ca_cert {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rfc4716_ca_keys = shift;
  my $cert = shift;
  my $priv_key = shift;
  my $addl_directives = shift;

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/ssh_host_rsa_key');
  my $dsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/ssh_host_dsa_key');

  my $authorized_ca_keys = File::Spec->rel2abs("$tmpdir/authorized_ca_keys");
  unless (copy($rfc4716_ca_keys, $authorized_ca_keys)) {
    die("Can't copy $rfc4716_ca_keys to $authorized_ca_keys: $!");
  }

  my $batch_file = File::Spec->rel2abs("$tmpdir/sftp-batch.txt");
  if (open(my $fh, "> $batch_file")) {
    print $fh "ls -al\n";

    unless (close($fh)) {
      die("Can't write $batch_file: $!");
    }

  } else {
    die("Can't open $batch_file: $!");
  }

  my $sftp_config = [
    'SFTPEngine on',
    "SFTPLog $setup->{log_file}",
    "SFTPHostKey $rsa_host_key",
    "SFTPHostKey $dsa_host_key",
    "SFTPAuthorizedUserCAKeys file:$authorized_ca_keys",
  ];
  if (defined($addl_directives)) {
    push(@$sftp_config, @$addl_directives);
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ssh2:30 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => $sftp_config,
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

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $sftp = 'sftp';

      my @cmd = (
        $sftp,
        '-oBatchMode=yes',
        '-oCheckHostIP=no',
        '-oCompression=yes',
        "-oPort=$port",
        '-oIdentitiesOnly=yes',
        "-oIdentityFile=$priv_key",
        "-oCertificateFile=$cert",
        '-oPubkeyAuthentication=yes',
        '-oStrictHostKeyChecking=no',
        '-oUpdateHostkeys=no',
        '-oUserKnownHostsFile=/dev/null',
        '-oHostKeyAlgorithms=ssh-rsa',
        '-vvv',
        '-b',
        "$batch_file",
        "$setup->{user}\@127.0.0.1",
      );

      my $sftp_rh = IO::Handle->new();
      my $sftp_wh = IO::Handle->new();
      my $sftp_eh = IO::Handle->new();

      $sftp_wh->autoflush(1);

      sleep(1);

      local $SIG{CHLD} = 'DEFAULT';

      # Make sure that the perms on the cert, key are what OpenSSH wants
      unless (chmod(0400, $cert, $priv_key)) {
        die("Can't set perms on $cert to 0400: $!");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Executing: ", join(' ', @cmd), "\n";
      }

      my $sftp_pid = open3($sftp_wh, $sftp_rh, $sftp_eh, @cmd);
      waitpid($sftp_pid, 0);
      my $exit_status = $?;

      # Restore the perms on the cert, key
      unless (chmod(0644, $cert, $priv_key)) {
        die("Can't set perms on $cert to 0644: $!");
      }

      my ($res, $errstr);
      if ($exit_status >> 8 == 0) {
        $errstr = join('', <$sftp_eh>);
        $res = 0;

      } else {
        $errstr = join('', <$sftp_eh>);
        $res = 1;
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Stderr: $errstr\n";
      }

      unless ($res == 0) {
        die("Can't list files on server: $errstr");
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /EXTENDED_REPLY limits\@openssh.com: .*$/) {
          $ok = 1;
          last;
        }
      }

      close($fh);

      $self->assert($ok,
        test_msg("Did not see expected log message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub sftp_ext_publickey_rsa_ca_rsa_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_rsa_ca_rsa_cert.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_rsa_ca_keys');

  sftp_ext_publickey_ca_cert($self, $rsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub sftp_ext_publickey_rsa_ca_ecdsa256_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa256_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_rsa_ca_ecdsa256_cert.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_rsa_ca_keys');

  sftp_ext_publickey_ca_cert($self, $rsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_rsa_ca_ecdsa384_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa384_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_rsa_ca_ecdsa384_cert.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_rsa_ca_keys');

  sftp_ext_publickey_ca_cert($self, $rsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_rsa_ca_ecdsa521_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa521_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_rsa_ca_ecdsa521_cert.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_rsa_ca_keys');

  sftp_ext_publickey_ca_cert($self, $rsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_rsa_ca_ed25519_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $eddsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_openssh_ed25519_key');
  my $eddsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_rsa_ca_ed25519_cert.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_rsa_ca_keys');

  sftp_ext_publickey_ca_cert($self, $rsa_rfc4716_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub sftp_ext_publickey_ecdsa256_ca_rsa_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa256_ca_rsa_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa256_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub sftp_ext_publickey_ecdsa256_ca_ecdsa256_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa256_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa256_ca_ecdsa256_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa256_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_ecdsa256_ca_ecdsa384_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa384_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa256_ca_ecdsa384_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa256_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_ecdsa256_ca_ecdsa521_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa521_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa256_ca_ecdsa521_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa256_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_ecdsa256_ca_ed25519_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $eddsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_openssh_ed25519_key');
  my $eddsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa256_ca_ed25519_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa256_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub sftp_ext_publickey_ecdsa384_ca_rsa_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa384_ca_rsa_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa384_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub sftp_ext_publickey_ecdsa384_ca_ecdsa256_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa256_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa384_ca_ecdsa256_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa384_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_ecdsa384_ca_ecdsa384_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa384_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa384_ca_ecdsa384_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa384_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_ecdsa384_ca_ecdsa521_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa521_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa384_ca_ecdsa521_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa384_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_ecdsa384_ca_ed25519_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $eddsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_openssh_ed25519_key');
  my $eddsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa384_ca_ed25519_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa384_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub sftp_ext_publickey_ecdsa521_ca_rsa_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa521_ca_rsa_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa521_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub sftp_ext_publickey_ecdsa521_ca_ecdsa256_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa256_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa521_ca_ecdsa256_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa521_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_ecdsa521_ca_ecdsa384_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa384_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa521_ca_ecdsa384_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa521_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_ecdsa521_ca_ecdsa521_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa521_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa521_ca_ecdsa521_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa521_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_ecdsa521_ca_ed25519_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $eddsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_openssh_ed25519_key');
  my $eddsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ecdsa521_ca_ed25519_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ecdsa521_ca_keys');

  sftp_ext_publickey_ca_cert($self, $ecdsa_rfc4716_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub sftp_ext_publickey_ed25519_ca_rsa_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ed25519_ca_rsa_cert.pub');
  my $eddsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ed25519_ca_keys');

  sftp_ext_publickey_ca_cert($self, $eddsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub sftp_ext_publickey_ed25519_ca_ecdsa256_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa256_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ed25519_ca_ecdsa256_cert.pub');
  my $eddsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ed25519_ca_keys');

  sftp_ext_publickey_ca_cert($self, $eddsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_ed25519_ca_ecdsa384_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa384_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ed25519_ca_ecdsa384_cert.pub');
  my $eddsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ed25519_ca_keys');

  sftp_ext_publickey_ca_cert($self, $eddsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_ed25519_ca_ecdsa521_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa521_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ed25519_ca_ecdsa521_cert.pub');
  my $eddsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ed25519_ca_keys');

  sftp_ext_publickey_ca_cert($self, $eddsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_publickey_ed25519_ca_ed25519_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $eddsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_openssh_ed25519_key');
  my $eddsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_ed25519_ca_ed25519_cert.pub');
  my $eddsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_ed25519_ca_keys');

  sftp_ext_publickey_ca_cert($self, $eddsa_rfc4716_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub sftp_ext_publickey_config_auth_certificates_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_rsa_ca_rsa_cert.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_rsa_ca_keys');

  my $addl_configs = [
    'SFTPAuthCertificates ssh-rsa-cert ssh-rsa-cert-v01@openssh.com rsa-sha2-512-cert-v01@openssh.com',
  ];

  sftp_ext_publickey_ca_cert($self, $rsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key, $addl_configs);
}

sub sftp_ext_publickey_certificate_options_allow_match_principals_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/user_rsa_ca_rsa_cert_match_principals.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_user_rsa_ca_keys');

  my $addl_configs = [
    'SFTPCertificateOptions AllowMatchPrincipals',
  ];

  sftp_ext_publickey_ca_cert($self, $rsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key, $addl_configs);
}

sub sftp_ext_hostbased_rsa_ca_rsa_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_rsa_ca_rsa_cert.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $rsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub sftp_ext_hostbased_rsa_ca_ecdsa256_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa256_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_rsa_ca_ecdsa256_cert.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $rsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_rsa_ca_ecdsa384_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa384_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_rsa_ca_ecdsa384_cert.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $rsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_rsa_ca_ecdsa521_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa521_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_rsa_ca_ecdsa521_cert.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $rsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_rsa_ca_ed25519_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $eddsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_openssh_ed25519_key');
  my $eddsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_rsa_ca_ed25519_cert.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $rsa_rfc4716_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa256_ca_rsa_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa256_ca_rsa_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa256_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa256_ca_ecdsa256_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa256_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa256_ca_ecdsa256_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa256_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa256_ca_ecdsa384_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa384_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa256_ca_ecdsa384_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa256_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa256_ca_ecdsa521_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa521_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa256_ca_ecdsa521_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa256_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa256_ca_ed25519_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $eddsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_openssh_ed25519_key');
  my $eddsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa256_ca_ed25519_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa256_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa384_ca_rsa_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa384_ca_rsa_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa384_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa384_ca_ecdsa256_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa256_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa384_ca_ecdsa256_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa384_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa384_ca_ecdsa384_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa384_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa384_ca_ecdsa384_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa384_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa384_ca_ecdsa521_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa521_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa384_ca_ecdsa521_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa384_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa384_ca_ed25519_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $eddsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_openssh_ed25519_key');
  my $eddsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa384_ca_ed25519_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa384_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa521_ca_rsa_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa521_ca_rsa_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa521_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa521_ca_ecdsa256_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa256_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa521_ca_ecdsa256_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa521_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa521_ca_ecdsa384_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa384_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa521_ca_ecdsa384_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa521_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa521_ca_ecdsa521_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa521_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa521_ca_ecdsa521_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa521_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_ecdsa521_ca_ed25519_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $eddsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_openssh_ed25519_key');
  my $eddsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ecdsa521_ca_ed25519_cert.pub');
  my $ecdsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ecdsa521_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $ecdsa_rfc4716_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub sftp_ext_hostbased_ed25519_ca_rsa_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ed25519_ca_rsa_cert.pub');
  my $eddsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ed25519_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $eddsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub sftp_ext_hostbased_ed25519_ca_ecdsa256_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa256_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ed25519_ca_ecdsa256_cert.pub');
  my $eddsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ed25519_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $eddsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_ed25519_ca_ecdsa384_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa384_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ed25519_ca_ecdsa384_cert.pub');
  my $eddsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ed25519_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $eddsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_ed25519_ca_ecdsa521_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $ecdsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_ecdsa521_key');
  my $ecdsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ed25519_ca_ecdsa521_cert.pub');
  my $eddsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ed25519_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $eddsa_rfc4716_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub sftp_ext_hostbased_ed25519_ca_ed25519_cert_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $eddsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_openssh_ed25519_key');
  my $eddsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_ed25519_ca_ed25519_cert.pub');
  my $eddsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_ed25519_ca_keys');

  sftp_ext_hostbased_ca_cert($self, $eddsa_rfc4716_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub sftp_ext_hostbased_certificate_options_allow_empty_principals_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_rsa_ca_rsa_cert_empty_principals.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys');

  my $addl_configs = [
    'SFTPCertificateOptions AllowEmptyPrincipals',
  ];

  sftp_ext_hostbased_ca_cert($self, $rsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key, $addl_configs);
}

sub sftp_ext_hostbased_certificate_options_allow_match_principals_issue2357 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/test_rsa_key');
  my $rsa_cert = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/host_rsa_ca_rsa_cert_match_principals.pub');
  my $rsa_rfc4716_ca_keys = File::Spec->rel2abs('t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys');

  my $addl_configs = [
    'SFTPCertificateOptions AllowMatchPrincipals',
  ];

  sftp_ext_hostbased_ca_cert($self, $rsa_rfc4716_ca_keys, $rsa_cert,
    $rsa_priv_key, $addl_configs);
}

1;
