package ProFTPD::Tests::Logging::ExtendedLog;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Compress::Raw::Zlib;
use Compress::Zlib;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use POSIX qw(:fcntl_h);

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite :features);

$| = 1;

my $order = 0;

my $TESTS = {
  extlog_retr_bug3137 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  extlog_stor_bug3137 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  extlog_site_cmds_bug3171 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  extlog_protocol => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  extlog_protocol_version_quoted_bug3383 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  extlog_rename_from => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  extlog_orig_user => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  extlog_bug1908 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
  },

  extlog_file_modified_bug3457 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  extlog_dele_bug3469 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  extlog_client_dir_bug3395 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  extlog_client_dir_chroot_bug3395 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
  },

  extlog_device_full => {
    order => ++$order,
    test_class => [qw(forking os_linux)],
  },

  extlog_uid_bug3390 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
  },

  extlog_gid_bug3390 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
  },

  extlog_pass_ok_var_s_bug3528 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  extlog_pass_failed_var_s_bug3528 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  extlog_ftp_raw_bytes_bug3554 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  extlog_ftp_sendfile_raw_bytes_bug3554 => {
    order => ++$order,
    test_class => [qw(bug feature_sendfile forking)],
  },

  extlog_ftp_deflate_raw_bytes_bug3554 => {
    order => ++$order,
    test_class => [qw(bug forking mod_deflate)],
  },

  extlog_ftps_raw_bytes_bug3554 => {
    order => ++$order,
    test_class => [qw(bug forking mod_tls)],
  },

  extlog_sftp_raw_bytes_bug3554 => {
    order => ++$order,
    test_class => [qw(bug forking mod_sftp)],
  },

  extlog_scp_raw_bytes_bug3554 => {
    order => ++$order,
    test_class => [qw(bug forking mod_sftp)],
  },

  extlog_exit_bug3559 => {
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
  $self->SUPER::set_up(@_);

  # Make sure that mod_sftp does not complain about permissions on the hostkey
  # files.

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/ssh_host_rsa_key');
  my $dsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/ssh_host_dsa_key');

  unless (chmod(0400, $rsa_host_key, $dsa_host_key)) {
    die("Can't set perms on $rsa_host_key, $dsa_host_key: $!");
  }
}

sub extlog_retr_bug3137 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%f"',
    ExtendedLog => "$ext_log READ custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

      my $conn = $client->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 30);
      $conn->close();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %f variable was
  # properly written out.  Bug#3137 occurred because the session.xfer.path
  # variable was cleared out, as part of cleaning up the data connection,
  # too early.  The fix is to use session.notes, which also has that path
  # information.
  if (open(my $fh, "< $ext_log")) {
    my $line = <$fh>;
    chomp($line);
    close($fh);

    $self->assert($test_file eq $line,
      test_msg("Expected '$test_file', got '$line'"));

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_stor_bug3137 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs("$tmpdir/foo");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%f"',
    ExtendedLog => "$ext_log WRITE custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

      my $conn = $client->stor_raw('foo');
      unless ($conn) {
        die("Failed to STOR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Foo!\n";
      $conn->write($buf, length($buf));
      $conn->close();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %f variable was
  # properly written out.  Bug#3137 occurred because the session.xfer.path
  # variable was cleared out, as part of cleaning up the data connection,
  # too early.  The fix is to use session.notes, which also has that path
  # information.
  if (open(my $fh, "< $ext_log")) {
    my $line = <$fh>;
    chomp($line);
    close($fh);

    $self->assert($test_file eq $line,
      test_msg("Expected '$test_file', got '$line'"));

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_site_cmds_bug3171 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    close($fh);

  } else {
    die("Can't open $test_file: $!");
  }

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $test_file)) {
      die("Can't set owner of $home_dir, $test_file to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%m"',
    ExtendedLog => "$ext_log ALL custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

      # Send a SITE command; Bug#3171 occurred because %m was not expanded
      # properly for SITE commands.

      my ($resp_code, $resp_msg);

      ($resp_code, $resp_msg) = $client->site('CHMOD', '0644', 'test.txt');

      my $expected;

      $expected = 200;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "SITE CHMOD command successful";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %m variable was
  # properly written out.  Bug#3171 occurred because %m, for SITE commands,
  # only contains 'SITE', and not the actual command used.

  if (open(my $fh, "< $ext_log")) {
    my $line;

    while ($line = <$fh>) {
      chomp($line);

      if ($line =~ /^SITE/) {
        last;
      }
    }

    close($fh);

    my $expected = 'SITE CHMOD';
    $self->assert($expected eq $line,
      test_msg("Expected '$expected', got '$line'"));

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_protocol {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    close($fh);

  } else {
    die("Can't open $test_file: $!");
  }

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $test_file)) {
      die("Can't set owner of $home_dir, $test_file to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%{protocol}"',
    ExtendedLog => "$ext_log ALL custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

      # Send a SITE command; Bug#3171 occurred because %m was not expanded
      # properly for SITE commands.

      my ($resp_code, $resp_msg);

      ($resp_code, $resp_msg) = $client->site('CHMOD', '0644', 'test.txt');

      my $expected;

      $expected = 200;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "SITE CHMOD command successful";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if (open(my $fh, "< $ext_log")) {
    my $line;

    while ($line = <$fh>) {
      chomp($line);

      if ($line =~ /^ftp/) {
        last;
      }
    }

    close($fh);

    my $expected = 'ftp';
    $self->assert($expected eq $line,
      test_msg("Expected '$expected', got '$line'"));

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_protocol_version_quoted_bug3383 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    close($fh);

  } else {
    die("Can't open $test_file: $!");
  }

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $test_file)) {
      die("Can't set owner of $home_dir, $test_file to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "\"%{protocol}\" \"%{version}\""',
    ExtendedLog => "$ext_log ALL custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

      # Send a SITE command; Bug#3171 occurred because %m was not expanded
      # properly for SITE commands.

      my ($resp_code, $resp_msg);

      ($resp_code, $resp_msg) = $client->site('CHMOD', '0644', 'test.txt');

      my $expected;

      $expected = 200;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "SITE CHMOD command successful";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  my $server_version = feature_get_version();

  if (open(my $fh, "< $ext_log")) {
    my $line;

    while ($line = <$fh>) {
      chomp($line);

      if ($line =~ /^"ftp" "(\S+)"/) {
        last;
      }
    }

    close($fh);

    my $expected = "\"ftp\" \"$server_version\"";
    $self->assert($expected eq $line,
      test_msg("Expected '$expected', got '$line'"));

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_rename_from {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $src_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $src_file")) {
    close($fh);

  } else {
    die("Can't open $src_file: $!");
  }

  my $dst_file = File::Spec->rel2abs("$tmpdir/foo.txt");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%w %f"',
    ExtendedLog => "$ext_log WRITE custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

      $client->rnfr('test.txt');
      my ($resp_code, $resp_msg) = $client->rnto('foo.txt');

      my $expected;

      $expected = 250;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Rename successful";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %f and %w variables were
  # properly written out.
  if (open(my $fh, "< $ext_log")) {
    my $line = <$fh>;
    chomp($line);

    my $expected = "- $src_file";
    $self->assert($expected eq $line,
      test_msg("Expected '$expected', got '$line'"));

    $line = <$fh>;
    chomp($line);

    $expected = "$src_file $dst_file";
    $self->assert($expected eq $line,
      test_msg("Expected '$expected', got '$line'"));

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_orig_user {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%U"',
    ExtendedLog => "$ext_log AUTH custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %f and %w variables were
  # properly written out.
  if (open(my $fh, "< $ext_log")) {
    my $line = <$fh>;
    chomp($line);

    my $expected = $user;
    $self->assert($expected eq $line,
      test_msg("Expected '$expected', got '$line'"));

    $line = <$fh>;
    chomp($line);

    $expected = $user;
    $self->assert($expected eq $line,
      test_msg("Expected '$expected', got '$line'"));

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_bug1908 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";

    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/ext.log");
  my $anon_ext_log = File::Spec->rel2abs("$tmpdir/anon-ext.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    ExtendedLog => "$ext_log READ",

    Anonymous => {
      $home_dir => [
        "User $user",
        "Group ftpd",
        "ExtendedLog $anon_ext_log READ",
        "ExtendedLog $ext_log NONE",
      ],
    },

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

      my $conn = $client->retr_raw('test.txt');
      unless ($conn) {
        die("Failed to RETR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 30);
      $conn->close();

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

  # Now, read in the ExtendedLogs.  Ideally we would NOT see anything in
  # the ExtendedLog defined in the "server config" context, and WOULD see
  # lines in the ExtendedLog defined in the <Anonymous> context.

  my $extlog_nlines = 0;
  if (open(my $fh, "< $ext_log")) {
    while (my $line = <$fh>) {
      $extlog_nlines++;
    }
    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  my $anon_extlog_nlines = 0;
  if (open(my $fh, "< $anon_ext_log")) {
    while (my $line = <$fh>) {
      $anon_extlog_nlines++;
    }
    close($fh);

  } else {
    die("Can't read $anon_ext_log: $!");
  }

  my $expected = 0;
  $self->assert($expected == $extlog_nlines,
    test_msg("Expected $expected, got $extlog_nlines"));

  $expected = 1;
  $self->assert($expected == $anon_extlog_nlines,
    test_msg("Expected $expected, got $anon_extlog_nlines"));

  unlink($log_file);
}

sub extlog_file_modified_bug3457 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $test_file = File::Spec->rel2abs("$home_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, world!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    LogFormat => 'custom "%{file-modified}"',
    ExtendedLog => "$ext_log WRITE custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("Failed to STOR test.txt: " . $client->response_code() . " " .
          $client->response_msg());
      }

      $conn->close();
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %{file-modified}
  # variable was properly written out.
  if (open(my $fh, "< $ext_log")) {
    my $line = <$fh>;
    chomp($line);
    close($fh);

    my $expected = 'true';
    $self->assert($expected eq $line,
      test_msg("Expected '$expected', got '$line'"));

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_dele_bug3469 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $test_file = File::Spec->rel2abs("$tmpdir/~test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";

    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%m %f"',
    ExtendedLog => "$ext_log ALL custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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
      $client->dele('~test.txt');
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %f variable was
  # properly written out.  Bug#3469 occurred because the session.xfer.path
  # variable was cleared out, as part of cleaning up the data connection,
  # too early.  The fix is to use session.notes, which also has that path
  # information.
  if (open(my $fh, "< $ext_log")) {
    while (my $line = <$fh>) {
      chomp($line);

      # We're only interested in the DELE log line
      unless ($line =~ /^DELE (.*)$/i) {
        next;
      }

      my $name = $1;
      my $expected = $test_file;
      $self->assert($expected eq $name,
        test_msg("Expected '$expected', got '$name'"));
    }

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_client_dir_bug3395 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/foo");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%m %d"',
    ExtendedLog => "$ext_log ALL custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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
      $client->cwd('foo');
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %d variable was
  # properly written out.  Bug#3395 says that even for QUIT, the %d
  # variable should be valid.
  if (open(my $fh, "< $ext_log")) {
    while (my $line = <$fh>) {
      chomp($line);

      # We're only interested in the QUIT log line
      unless ($line =~ /^QUIT (.*)$/i) {
        next;
      }

      my $name = $1;
      my $expected = $sub_dir;
      $self->assert($expected eq $name,
        test_msg("Expected '$expected', got '$name'"));
    }

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_client_dir_chroot_bug3395 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/foo");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    DefaultRoot => '~',

    LogFormat => 'custom "%m %d"',
    ExtendedLog => "$ext_log ALL custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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
      $client->cwd('foo');
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %d variable was
  # properly written out.  Bug#3395 says that even for QUIT, the %d
  # variable should be valid.
  if (open(my $fh, "< $ext_log")) {
    while (my $line = <$fh>) {
      chomp($line);

      # We're only interested in the QUIT log line
      unless ($line =~ /^QUIT (.*)$/i) {
        next;
      }

      my $name = $1;
      my $expected = '/foo';
      $self->assert($expected eq $name,
        test_msg("Expected '$expected', got '$name'"));
    }

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_device_full {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/foo");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  # XXX The /dev/full device only exists on Linux, as far as I know
  my $ext_log = File::Spec->rel2abs('/dev/full');

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%m %d"',
    ExtendedLog => "$ext_log ALL custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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
      $client->cwd('foo');
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub extlog_uid_bug3390 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%{uid}"',
    ExtendedLog => "$ext_log READ custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

      my $conn = $client->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 30);
      $conn->close();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %{uid} variable was
  # properly written out.
  if (open(my $fh, "< $ext_log")) {
    my $line = <$fh>;
    chomp($line);
    close($fh);

    $self->assert($uid == $line,
      test_msg("Expected $uid, got '$line'"));

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_gid_bug3390 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%{gid}"',
    ExtendedLog => "$ext_log READ custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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

      my $conn = $client->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 30);
      $conn->close();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %{gid} variable was
  # properly written out.
  if (open(my $fh, "< $ext_log")) {
    my $line = <$fh>;
    chomp($line);
    close($fh);

    $self->assert($gid == $line,
      test_msg("Expected $gid, got '$line'"));

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_pass_ok_var_s_bug3528 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'response:10',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%m %s %S"',
    ExtendedLog => "$ext_log AUTH custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %s variable was
  # properly written out for the PASS command.
  if (open(my $fh, "< $ext_log")) {
    while (my $line = <$fh>) {
      chomp($line);

      if ($line =~ /^(\S+) (\S+) (.*$)$/) {
        my $cmd = $1;
        my $resp_code = $2;
        my $resp_msg = $3;

        next unless $cmd eq 'PASS';

        my $expected = 230;
        $self->assert($expected == $resp_code,
          test_msg("Expected $expected, got $resp_code"));

        $expected = "User $user logged in";
        $self->assert($expected eq $resp_msg,
          test_msg("Expected '$expected', got '$resp_msg'"));

        last;
      }
    }

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_pass_failed_var_s_bug3528 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'response:10',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%m %s %S"',
    ExtendedLog => "$ext_log AUTH custom",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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
      eval { $client->login($user, 'foobar') };
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
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %s variable was
  # properly written out for the PASS command.
  if (open(my $fh, "< $ext_log")) {
    while (my $line = <$fh>) {
      chomp($line);

      if ($line =~ /^(\S+) (\S+) (.*$)$/) {
        my $cmd = $1;
        my $resp_code = $2;
        my $resp_msg = $3;

        next unless $cmd eq 'PASS';

        my $expected = 530;
        $self->assert($expected == $resp_code,
          test_msg("Expected $expected, got $resp_code"));

        $expected = "Login incorrect.";
        $self->assert($expected eq $resp_msg,
          test_msg("Expected '$expected', got '$resp_msg'"));

        last;
      }
    }

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_ftp_raw_bytes_bug3554 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'response:10',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%{protocol} %m \"%S\" %I %O"',
    ExtendedLog => "$ext_log ALL custom",
    ServerIdent => 'on "FTP Server"',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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
      $client->type('ascii');

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "ABCD\n" x 8;
      $conn->write($buf, length($buf), 30);
      $conn->close();

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      $client->quit();

      my $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %I/%O variables
  # are properly populated
  if (open(my $fh, "< $ext_log")) {
    while (my $line = <$fh>) {
      chomp($line);

      if ($line =~ /^\S+ (\S+) (.*?) (\d+) (\d+)$/) {
        my $cmd = $1;
        my $resp = $2;
        my $bytes_in = $3;
        my $bytes_out = $4;

        # Only watch for the QUIT command, to get the session total.
        next unless $cmd eq 'QUIT';

        my $expected = 108;
        $self->assert($expected == $bytes_in,
          test_msg("Expected $expected, got $bytes_in"));

        # Why would this number vary so widely?  It's because of the notation
        # used to express the port number in a PASV response.  That port
        # number is ephemeral, chosen by the kernel.

        my $expected_min = 232;
        my $expected_max = 236;
        $self->assert($expected_min <= $bytes_out &&
                      $expected_max >= $bytes_out,
          test_msg("Expected $expected_min - $expected_max, got $bytes_out"));
      }
    }

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_ftp_sendfile_raw_bytes_bug3554 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "ABCD\n" x 8;
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'response:10',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%{protocol} %m \"%S\" %I %O"',
    ExtendedLog => "$ext_log ALL custom",
    ServerIdent => 'on "FTP Server"',

    UseSendfile => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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
      $client->type('binary');

      my $conn = $client->retr_raw('test.txt');
      unless ($conn) {
        die("RETR test.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 16382, 30);
      $conn->close();

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      $client->quit();

      my $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %I/%O variables
  # are properly populated
  if (open(my $fh, "< $ext_log")) {
    while (my $line = <$fh>) {
      chomp($line);

      if ($line =~ /^\S+ (\S+) (.*?) (\d+) (\d+)$/) {
        my $cmd = $1;
        my $resp = $2;
        my $bytes_in = $3;
        my $bytes_out = $4;

        # Only watch for the QUIT command, to get the session total.
        next unless $cmd eq 'QUIT';

        my $expected = 60;
        $self->assert($expected == $bytes_in,
          test_msg("Expected $expected, got $bytes_in"));

        # Why would this number vary so widely?  It's because of the notation
        # used to express the port number in a PASV response.  That port
        # number is ephemeral, chosen by the kernel.

        my $expected_min = 284;
        my $expected_max = 288;
        $self->assert($expected_min <= $bytes_out &&
                      $expected_max >= $bytes_out,
          test_msg("Expected $expected_min - $expected_max, got $bytes_out"));
      }
    }

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

#  unlink($log_file);
}

sub extlog_ftp_deflate_raw_bytes_bug3554 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 deflate:10',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    TimeoutLinger => 1,

    LogFormat => 'custom "%{protocol} %m \"%S\" %I %O"',
    ExtendedLog => "$ext_log ALL custom",
    ServerIdent => 'on "FTP Server"',

    IfModules => {
      'mod_deflate.c' => {
        DeflateEngine => 'on',
        DeflateLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
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
      $client->mode('Z');

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "ABCD\n" x 8;
      my $deflated = compress($buf);
      $conn->write($deflated, length($deflated), 30);
      $conn->close();

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      $client->quit();

      my $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %I/%O variables
  # are properly populated
  if (open(my $fh, "< $ext_log")) {
    while (my $line = <$fh>) {
      chomp($line);

      if ($line =~ /^\S+ (\S+) (.*?) (\d+) (\d+)$/) {
        my $cmd = $1;
        my $resp = $2;
        my $bytes_in = $3;
        my $bytes_out = $4;

        # Only watch for the QUIT command, to get the session total.
        next unless $cmd eq 'QUIT';

        my $expected = 100;
        $self->assert($expected == $bytes_in,
          test_msg("Expected $expected, got $bytes_in"));

        # Why would this number vary so widely?  It's because of the notation
        # used to express the port number in a PASV response.  That port
        # number is ephemeral, chosen by the kernel.

        my $expected_min = 221;
        my $expected_max = 225;
        $self->assert($expected_min <= $bytes_out &&
                      $expected_max >= $bytes_out,
          test_msg("Expected $expected_min - $expected_max, got $bytes_out"));
      }
    }

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub extlog_ftps_raw_bytes_bug3554 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $src_file = File::Spec->rel2abs("$tmpdir/src.txt");
  if (open(my $fh, "> $src_file")) {
    print $fh "ABCD\n" x 8192;
    unless (close($fh)) {
      die("Can't write $src_file: $!");
    }

  } else {
    die("Can't open $src_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'response:10',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%{protocol} %m \"%S\" %I %O"',
    ExtendedLog => "$ext_log ALL custom",
    ServerIdent => 'on "FTP Server"',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $log_file,
        TLSProtocol => 'SSLv3 TLSv1',
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'NoSessionReuseRequired',
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

  require Net::FTPSSL;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Give the server a chance to start up
      sleep(2);

      my $client = Net::FTPSSL->new('127.0.0.1',
        Encryption => 'E',
        Port => $port,
      );

      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      unless ($client->login($user, $passwd)) {
        die("Can't login: " . $client->last_message());
      }

      unless ($client->binary()) {
        die("Can't set transfer mode to binary: " . $client->last_message());
      }

      unless ($client->put($src_file, 'test.txt')) {
        die("Can't upload '$src_file' to 'test.txt': " .
          $client->last_message());
      }

      $client->quit();

      unless (-f $test_file) {
        die("File $test_file does not exist as expected");
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, 30) };
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

  # Now, read in the ExtendedLog, and see whether the %I/%O variables
  # are properly populated
  if (open(my $fh, "< $ext_log")) {
    while (my $line = <$fh>) {
      chomp($line);

      if ($line =~ /^\S+ (\S+) (.*?) (\d+) (\d+)$/) {
        my $cmd = $1;
        my $resp = $2;
        my $bytes_in = $3;
        my $bytes_out = $4;

        # Only watch for the QUIT command, to get the session total.
        next unless $cmd eq 'QUIT';

        # The expected bytes in/out will vary on the ciphers used, etc.
        my $expected_min = 42340;
        my $expected_max = 42358;
        $self->assert($expected_min <= $bytes_in &&
                      $expected_max >= $bytes_in,
          test_msg("Expected $expected_min - $expected_max, got $bytes_in"));

        $expected_min = 6828;
        $expected_max = 6848;
        $self->assert($expected_min <= $bytes_out &&
                      $expected_max >= $bytes_out,
          test_msg("Expected $expected_min - $expected_max, got $bytes_out"));
      }
    }

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  unlink($log_file);
}

sub extlog_sftp_raw_bytes_bug3554 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/ssh_host_rsa_key');
  my $dsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/ssh_host_dsa_key');

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 ssh2:20 sftp:20 scp:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%{protocol} %m \"%S\" %I %O"',
    ExtendedLog => "$ext_log ALL custom",
    ServerIdent => 'on "FTP Server"',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $log_file",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($user, $passwd)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open('test.txt', O_WRONLY|O_CREAT|O_TRUNC, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.txt: [$err_name] ($err_code)");
      }

      print $fh "ABCD\n" x 8192;

      # To issue the FXP_CLOSE, we have to explicitly destroy the filehandle
      $fh = undef;

      # To issue the CHANNEL_CLOSE, we have to explicitly destroy the sftp
      # object.  Sigh.
      $sftp = undef;

      $ssh2->disconnect();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

  # Now, read in the ExtendedLog, and see whether the %I/%O variables
  # are properly populated
  if (open(my $fh, "< $ext_log")) {
    while (my $line = <$fh>) {
      chomp($line);

      if ($line =~ /^\S+ (\S+) (.*?) (\d+) (\d+)$/) {
        my $cmd = $1;
        my $resp = $2;
        my $bytes_in = $3;
        my $bytes_out = $4;

        # Only watch for the CHANNEL_CLOSE command, to get the session total.
        next unless $cmd eq 'CHANNEL_CLOSE';

        # The expected bytes in/out will vary on the ciphers used, etc.
        my $expected_min = 34147;
        my $expected_max = 34147;
        $self->assert($expected_min <= $bytes_in &&
                      $expected_max >= $bytes_in,
          test_msg("Expected $expected_min - $expected_max, got $bytes_in"));

        $expected_min = 2156;
        $expected_max = 2196;
        $self->assert($expected_min <= $bytes_out &&
                      $expected_max >= $bytes_out,
          test_msg("Expected $expected_min - $expected_max, got $bytes_out"));
      }
    }

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  unlink($log_file);
}

sub extlog_scp_raw_bytes_bug3554 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/ssh_host_rsa_key');
  my $dsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp/ssh_host_dsa_key');

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $src_file = File::Spec->rel2abs("$tmpdir/src.txt");
  if (open(my $fh, "> $src_file")) {
    print $fh "ABCD\n" x 8192;
    unless (close($fh)) {
      die("Can't write $src_file: $!");
    }

  } else {
    die("Can't open $src_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 ssh2:20 sftp:20 scp:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%{protocol} %m \"%S\" %I %O"',
    ExtendedLog => "$ext_log ALL custom",
    ServerIdent => 'on "FTP Server"',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $log_file",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($user, $passwd)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $res = $ssh2->scp_put($src_file, 'test.txt');
      unless ($res) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't upload $src_file to server: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();

      unless (-f $test_file) {
        die("File $test_file does not exist as expected");
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

  # Now, read in the ExtendedLog, and see whether the %I/%O variables
  # are properly populated
  if (open(my $fh, "< $ext_log")) {
    while (my $line = <$fh>) {
      chomp($line);

      if ($line =~ /^\S+ (\S+) (.*?) (\d+) (\d+)$/) {
        my $cmd = $1;
        my $resp = $2;
        my $bytes_in = $3;
        my $bytes_out = $4;

        # Only watch for the CHANNEL_CLOSE command, to get the session total.
        next unless $cmd eq 'CHANNEL_CLOSE';

        # The expected bytes in/out will vary on the ciphers used, etc.
        my $expected_min = 42787;
        my $expected_max = 42787;
        $self->assert($expected_min <= $bytes_in &&
                      $expected_max >= $bytes_in,
          test_msg("Expected $expected_min - $expected_max, got $bytes_in"));

        $expected_min = 1996;
        $expected_max = 2036;
        $self->assert($expected_min <= $bytes_out &&
                      $expected_max >= $bytes_out,
          test_msg("Expected $expected_min - $expected_max, got $bytes_out"));
      }
    }

    close($fh);

  } else {
    die("Can't read $ext_log: $!");
  }

  unlink($log_file);
}

sub extlog_exit_bug3559 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/extlog.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/extlog.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/extlog.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/extlog.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/extlog.group");

  my $test_file = File::Spec->rel2abs($config_file);

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'response:10',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    LogFormat => 'custom "%{protocol} %m \"%S\" %I %O"',
    ExtendedLog => "$ext_log EXIT custom",
    ServerIdent => 'on "FTP Server"',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
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
      $client->type('ascii');

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "ABCD\n" x 8;
      $conn->write($buf, length($buf), 30);
      $conn->close();

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      $client->quit();

      my $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  # Now, read in the ExtendedLog, and see whether the %I/%O variables
  # are properly populated
  if (open(my $fh, "< $ext_log")) {
    my $ok = 0;

    while (my $line = <$fh>) {
      chomp($line);

      if ($line =~ /^\S+ (\S+) (.*?) (\d+) (\d+)$/) {
        my $cmd = $1;
        my $resp = $2;
        my $bytes_in = $3;
        my $bytes_out = $4;

        # Only watch for the EXIT command, to get the session total.
        next unless $cmd eq 'EXIT';

        my $expected = 108;
        $self->assert($expected == $bytes_in,
          test_msg("Expected $expected, got $bytes_in"));

        # Why would this number vary so widely?  It's because of the notation
        # used to express the port number in a PASV response.  That port
        # number is ephemeral, chosen by the kernel.

        my $expected_min = 232;
        my $expected_max = 236;
        $self->assert($expected_min <= $bytes_out &&
                      $expected_max >= $bytes_out,
          test_msg("Expected $expected_min - $expected_max, got $bytes_out"));

        $ok = 1;
      }
    }

    close($fh);
    $self->assert($ok == 1,
      test_msg("Did not find expected ExtendedLog lines"));

  } else {
    die("Can't read $ext_log: $!");
  }

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

1;
