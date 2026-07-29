package ProFTPD::Tests::Modules::mod_procfs::sftp;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Cwd;
use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use IPC::Open3;
use POSIX qw(:fcntl_h);
use Socket;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  procfs_sftp_open_readonly => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_open_readwrite => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_lstat => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_mkdir => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_opendir => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_readlink => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_realpath => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_remove => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_rename => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_rmdir => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_setstat => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_stat => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_symlink => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  procfs_sftp_ext_hardlink => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  # TODO
  # procfs_sftp_link
};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  # Check for the required Perl modules:
  #
  #  Net-SSH2
  #  Net-SSH2-SFTP

  my $required = [qw(
    Net::SSH2
    Net::SSH2::SFTP
  )];

  foreach my $req (@$required) {
    eval "use $req";
    if ($@) {
      print STDERR "\nWARNING:\n + Module '$req' not found, skipping all tests\n";

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Unable to load $req: $@\n";
      }

      return qw(testsuite_empty_test);
    }
  }

  return testsuite_get_runnable_tests($TESTS);
}

sub set_up {
  my $self = shift;
  $self->SUPER::set_up(@_);

  # Make sure that mod_sftp does not complain about permissions on the hostkey
  # files.

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  unless (chmod(0400, $rsa_host_key, $dsa_host_key)) {
    die("Can't set perms on $rsa_host_key, $dsa_host_key: $!");
  }
}

sub procfs_sftp_open_readonly {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open($test_file, O_RDONLY);
      if ($fh) {
        die("OPEN $test_file succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_NO_SUCH_FILE';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 2;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /RETR $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_open_readwrite {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open($test_file, O_RDWR|O_CREAT);
      if ($fh) {
        die("OPEN $test_file succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_NO_SUCH_FILE';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 2;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /STOR $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_lstat {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $st = $sftp->stat($test_file, 0);
      if ($st) {
        die("LSTAT $test_file succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /LSTAT $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_mkdir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $test_path = '/proc/test.d';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $res = $sftp->mkdir($test_path);
      if ($res) {
        die("MKDIR $test_path succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /MKD $test_path denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_opendir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $test_path = '/proc/test.d';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $dir = $sftp->opendir($test_path);
      if ($dir) {
        die("OPENDIR $test_path succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /OPENDIR $test_path denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_readlink {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $res = $sftp->readlink($test_file);
      if ($res) {
        die("READLINK $test_file succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /READLINK $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_realpath {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $res = $sftp->realpath($test_file);
      if ($res) {
        die("REALPATH $test_file succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /REALPATH $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_remove {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $res = $sftp->unlink($test_file);
      if ($res) {
        die("REMOVE $test_file succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /DELE $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_rename {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $from_file = '/proc/src.txt';
  my $to_file = '/proc/dst.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $res = $sftp->rename($from_file, 'dst.txt');
      if ($res) {
        die("RENAME $from_file succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $res = $sftp->rename('src.txt', $to_file);
      if ($res) {
        die("RENAME $to_file succeeded unexpectedly");
      }

      ($err_code, $err_name) = $sftp->error();

      $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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
      my $from_ok = 0;
      my $to_ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /RNFR $from_file denied by mod_procfs/) {
          $from_ok = 1;
        }

        if ($line =~ /RNTO $to_file denied by mod_procfs/) {
          $to_ok = 1;
        }

        if ($from_ok && $to_ok) {
          last;
        }
      }

      close($fh);
      $self->assert($from_ok && $to_ok,
        test_msg("Did not see expected ProcfsLog messages"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_rmdir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $test_path = '/proc/test.d';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $res = $sftp->rmdir($test_path);
      if ($res) {
        die("RMDIR $test_path succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /RMD $test_path denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_setstat {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $res = $sftp->setstat($test_file,
        atime => 0,
        mtime => 0
      );
      if ($res) {
        die("SETSTAT $test_file succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /SETSTAT $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_stat {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $test_file = '/proc/test.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $st = $sftp->stat($test_file, 1);
      if ($st) {
        die("STAT $test_file succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /STAT $test_file denied by mod_procfs/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_symlink {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $from_file = '/proc/src.txt';
  my $to_file = '/proc/dst.txt';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $res = $sftp->symlink($from_file, 'dst.txt');
      if ($res) {
        die("SYMLINK $from_file succeeded unexpectedly");
      }

      my ($err_code, $err_name) = $sftp->error();

      my $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $res = $sftp->symlink('src.txt', $to_file);
      if ($res) {
        die("SYMLINK $to_file succeeded unexpectedly");
      }

      ($err_code, $err_name) = $sftp->error();

      $expected = 'SSH_FX_PERMISSION_DENIED';
      $self->assert($expected eq $err_name,
        test_msg("Expected error name '$expected', got '$err_name'"));

      $expected = 3;
      $self->assert($expected == $err_code,
        test_msg("Expected error code $expected, got $err_code"));

      $sftp = undef;
      $ssh2->disconnect();
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
      my $from_ok = 0;
      my $to_ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /SYMLINK $from_file denied by mod_procfs/) {
          $from_ok = 1;
        }

        if ($line =~ /SYMLINK $to_file denied by mod_procfs/) {
          $to_ok = 1;
        }

        if ($from_ok && $to_ok) {
          last;
        }
      }

      close($fh);
      $self->assert($from_ok && $to_ok,
        test_msg("Did not see expected ProcfsLog messages"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

sub procfs_sftp_ext_hardlink {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'procfs');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  my $from_file = '/proc/src.txt';
  my $to_file = '/proc/dst.txt';

  # As Net::SSH2::SFTP (via libssh2) does not implement LINK, we'll use
  # OpenSSH's sftp(1) and its "hardlink@openssh.com" extension.

  my $batch_file = File::Spec->rel2abs("$tmpdir/sftp-batch.conf");
  if (open(my $fh, "> $batch_file")) {
    print $fh "ln $from_file $to_file\n";

    unless (close($fh)) {
      die("Can't write $batch_file: $!");
    }

  } else {
    die("Can't open $batch_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'procfs:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_procfs.c' => {
        ProcfsEngine => 'on',
        ProcfsLog => $setup->{log_file},
      },

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",

        "SFTPAuthorizedUserKeys file:~/.authorized_keys",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(1);

      my $sftp = 'sftp';

      my @cmd = (
        $sftp,
        '-oBatchMode=yes',
        '-oCheckHostIP=no',
        '-oCompression=yes',
        "-oPort=$port",
        "-oIdentityFile=$rsa_priv_key",
        '-oIdentitiesOnly=yes',
        '-oPubkeyAuthentication=yes',
        '-oStrictHostKeyChecking=no',
        '-oUserKnownHostsFile=/dev/null',
        '-vvv',
        '-b',
        $batch_file,
        "$setup->{user}\@127.0.0.1",
      );

      my $sftp_rh = IO::Handle->new();
      my $sftp_wh = IO::Handle->new();
      my $sftp_eh = IO::Handle->new();

      $sftp_wh->autoflush(1);

      sleep(1);

      local $SIG{CHLD} = 'DEFAULT';

      # Make sure that the perms on the priv key are what OpenSSH wants
      unless (chmod(0400, $rsa_priv_key)) {
        die("Can't set perms on $rsa_priv_key to 0400: $!");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Executing: ", join(' ', @cmd), "\n";
      }

      my $sftp_pid = open3($sftp_wh, $sftp_rh, $sftp_eh, @cmd);
      waitpid($sftp_pid, 0);
      my $exit_status = $?;

      # Restore the perms on the priv key
      unless (chmod(0644, $rsa_priv_key)) {
        die("Can't set perms on $rsa_priv_key to 0644: $!");
      }

      my ($res, $errstr);
      if ($exit_status >> 8 == 0) {
        $errstr = join('', <$sftp_eh>);
        $res = 0;

      } else {
        $errstr = join('', <$sftp_eh>);
        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Stderr: $errstr\n";
        }

        $res = 1;
      }

      if ($res == 0) {
        die("Hardlink $from_file on server succeeded unexpectedly");
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

        next unless $line =~ /mod_procfs\//;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /HARDLINK $from_file denied by mod_procfs/) {
          $ok = 1;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected ProcfsLog messages"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup, $ex);
}

1;
