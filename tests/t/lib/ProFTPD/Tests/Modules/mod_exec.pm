package ProFTPD::Tests::Modules::mod_exec;

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
  exec_on_connect => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  exec_on_cmd => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  exec_on_cmd_var_total_bytes_xfer => {
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

sub set_up {
  my $self = shift;
  $self->{tmpdir} = testsuite_get_tmp_dir();

  # Create temporary scratch dir
  eval { mkpath($self->{tmpdir}) };
  if ($@) {
    my $abs_path = File::Spec->rel2abs($self->{tmpdir});
    die("Can't create dir $abs_path: $@");
  }
}

sub tear_down {
  my $self = shift;

  # Remove temporary scratch dir
  if ($self->{tmpdir}) {
    eval { rmtree($self->{tmpdir}) };
  }

  undef $self;
}

sub exec_on_connect {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/exec.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/exec.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/exec.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $ban_tab = File::Spec->rel2abs("$tmpdir/exec.tab");

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/exec.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/exec.group");

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

  my $connect_file = File::Spec->rel2abs("$tmpdir/connect.txt");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_exec.c' => {
        ExecEngine => 'on',
        ExecLog => $log_file,
        ExecOnConnect => "/bin/bash -c \"echo %a > $connect_file\"",
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

  if (open(my $fh, "< $connect_file")) {
    my $line = <$fh>;
    close($fh);

    chomp($line);

    my $expected = '127.0.0.1';

    $self->assert($expected eq $line,
      test_msg("Expected '$expected', got '$line'"));

  } else {
    die("Can't read $connect_file: $!");
  }

  unlink($log_file);
}

sub exec_on_cmd {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/exec.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/exec.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/exec.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $ban_tab = File::Spec->rel2abs("$tmpdir/exec.tab");

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/exec.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/exec.group");

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

  my $cmd_file = File::Spec->rel2abs("$tmpdir/cmd.txt");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_exec.c' => {
        ExecEngine => 'on',
        ExecLog => $log_file,
        ExecOnCommand => "LIST,NLST /bin/bash -c \"echo %a > $cmd_file\"",
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
      $client->list();
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

  if (open(my $fh, "< $cmd_file")) {
    my $line = <$fh>;
    close($fh);

    chomp($line);

    my $expected = '127.0.0.1';

    $self->assert($expected eq $line,
      test_msg("Expected '$expected', got '$line'"));

  } else {
    die("Can't read $cmd_file: $!");
  }

  unlink($log_file);
}

sub exec_on_cmd_var_total_bytes_xfer {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/exec.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/exec.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/exec.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $ban_tab = File::Spec->rel2abs("$tmpdir/exec.tab");

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/exec.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/exec.group");

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

  my $cmd_file = File::Spec->rel2abs("$tmpdir/cmd.txt");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_exec.c' => {
        ExecEngine => 'on',
        ExecLog => $log_file,
        ExecOnCommand => "LIST,NLST /bin/bash -c \"echo %{total_bytes_xfer} > $cmd_file\"",
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
      $client->list();
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

  if (open(my $fh, "< $cmd_file")) {
    my $line = <$fh>;
    close($fh);

    chomp($line);

    my $expected = '\d+';

    $self->assert(qr/$expected/, $line,
      test_msg("Expected '$expected', got '$line'"));

  } else {
    die("Can't read $cmd_file: $!");
  }

  unlink($log_file);
}

1;
