package ProFTPD::Tests::Commands::SIZE;

use lib qw(t/lib);
use base qw(Test::Unit::TestCase ProFTPD::TestSuite::Child);
use strict;

use File::Path qw(mkpath rmtree);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :module :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  size_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  size_fails_ascii => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  size_fails_enoent => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  size_fails_eperm => {
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

sub size_ok {
  my $self = shift;

  my $config_file = 'tmp/cmds.conf';
  my $pid_file = File::Spec->rel2abs('tmp/cmds.pid');
  my $scoreboard_file = File::Spec->rel2abs('tmp/cmds.scoreboard');
  my $log_file = File::Spec->rel2abs('cmds.log');

  my $auth_user_file = File::Spec->rel2abs('tmp/cmds.passwd');
  my $auth_group_file = File::Spec->rel2abs('tmp/cmds.group');

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs('tmp');

  my $test_file = File::Spec->rel2abs('tmp/foo');
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    close($fh);

  } else {
    die("Can't create $test_file: $!");
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
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($readh, $writeh);
  unless (pipe($readh, $writeh)) {
    die("Can't open pipe: $!");
  }

  $writeh->autoflush(1);

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      eval { $client->login($user, $passwd) };
      if ($@) {
        my $err = $@;
        print $writeh "done\n";
        die("Failed to log in: $err");
      }

      eval { $client->type('binary') };
      if ($@) {
        my $err = $@;
        print $writeh "done\n";
        die("Failed to TYPE: $err");
      }
    
      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->size($test_file) };
      if ($@) {
        my $err = $@;
        print $writeh "done\n";
        die("Failed to SIZE: $err");
      }

      my $expected;

      $expected = 213;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = 14;
      chomp($resp_msg);
      $self->assert($expected == $resp_msg,
        test_msg("Expected $expected, got $resp_msg"));
    };

    if ($@) {
      $ex = $@;
    }

    print $writeh "done\n";

  } else {
    # Start server
    server_start($config_file);

    # Wait until we receive word from the child that it has finished its
    # test.
    while (my $msg = <$readh>) {
      chomp($msg);

      if ($msg eq 'done') {
        last;
      }
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

sub size_fails_ascii {
  my $self = shift;

  my $config_file = 'tmp/cmds.conf';
  my $pid_file = File::Spec->rel2abs('tmp/cmds.pid');
  my $scoreboard_file = File::Spec->rel2abs('tmp/cmds.scoreboard');
  my $log_file = File::Spec->rel2abs('cmds.log');

  my $auth_user_file = File::Spec->rel2abs('tmp/cmds.passwd');
  my $auth_group_file = File::Spec->rel2abs('tmp/cmds.group');

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs('tmp');

  my $test_file = File::Spec->rel2abs('tmp/foo');

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
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($readh, $writeh);
  unless (pipe($readh, $writeh)) {
    die("Can't open pipe: $!");
  }

  $writeh->autoflush(1);

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      eval { $client->login($user, $passwd) };
      if ($@) {
        my $err = $@;
        print $writeh "done\n";
        die("Failed to log in: $err");
      }

      eval { $client->type('ascii') };
      if ($@) {
        my $err = $@;
        print $writeh "done\n";
        die("Failed to TYPE: $err");
      }
    
      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->size($test_file) };
      unless ($@) {
        print $writeh "done\n";
        die("SIZE succeeded unexpectedly");

      } else {
        $resp_code = $client->response_code();
        $resp_msg = $client->response_msg();
      }

      my $expected;

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "SIZE not allowed in ASCII mode";
      chomp($resp_msg);
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    print $writeh "done\n";

  } else {
    # Start server
    server_start($config_file);

    # Wait until we receive word from the child that it has finished its
    # test.
    while (my $msg = <$readh>) {
      chomp($msg);

      if ($msg eq 'done') {
        last;
      }
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

sub size_fails_enoent {
  my $self = shift;

  my $config_file = 'tmp/cmds.conf';
  my $pid_file = File::Spec->rel2abs('tmp/cmds.pid');
  my $scoreboard_file = File::Spec->rel2abs('tmp/cmds.scoreboard');
  my $log_file = File::Spec->rel2abs('cmds.log');

  my $auth_user_file = File::Spec->rel2abs('tmp/cmds.passwd');
  my $auth_group_file = File::Spec->rel2abs('tmp/cmds.group');

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs('tmp');

  my $test_file = File::Spec->rel2abs('tmp/foo');

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
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($readh, $writeh);
  unless (pipe($readh, $writeh)) {
    die("Can't open pipe: $!");
  }

  $writeh->autoflush(1);

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      eval { $client->login($user, $passwd) };
      if ($@) {
        my $err = $@;
        print $writeh "done\n";
        die("Failed to log in: $err");
      }

      eval { $client->type('binary') };
      if ($@) {
        my $err = $@;
        print $writeh "done\n";
        die("Failed to TYPE: $err");
      }
    
      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->size($test_file) };
      unless ($@) {
        print $writeh "done\n";
        die("SIZE succeeded unexpectedly");

      } else {
        $resp_code = $client->response_code();
        $resp_msg = $client->response_msg();
      }

      my $expected;

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "$test_file: No such file or directory";
      chomp($resp_msg);
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    print $writeh "done\n";

  } else {
    # Start server
    server_start($config_file);

    # Wait until we receive word from the child that it has finished its
    # test.
    while (my $msg = <$readh>) {
      chomp($msg);

      if ($msg eq 'done') {
        last;
      }
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

sub size_fails_eperm {
  my $self = shift;

  my $config_file = 'tmp/cmds.conf';
  my $pid_file = File::Spec->rel2abs('tmp/cmds.pid');
  my $scoreboard_file = File::Spec->rel2abs('tmp/cmds.scoreboard');
  my $log_file = File::Spec->rel2abs('cmds.log');

  my $auth_user_file = File::Spec->rel2abs('tmp/cmds.passwd');
  my $auth_group_file = File::Spec->rel2abs('tmp/cmds.group');

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs('tmp');

  my $test_file = File::Spec->rel2abs('tmp/foo');
  if (open(my $fh, "> $test_file")) {
    close($fh);

  } else {
    die("Can't create $test_file: $!");
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
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($readh, $writeh);
  unless (pipe($readh, $writeh)) {
    die("Can't open pipe: $!");
  }

  $writeh->autoflush(1);

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      eval { $client->login($user, $passwd) };
      if ($@) {
        my $err = $@;
        print $writeh "done\n";
        die("Failed to log in: $err");
      }

      eval { $client->type('binary') };
      if ($@) {
        my $err = $@;
        print $writeh "done\n";
        die("Failed to TYPE: $err");
      }
    
      # Make it such that perms on the home dir do not allow reads
      my $perms = (stat($home_dir))[2];
      unless (chmod(0220, $home_dir)) {
        my $err = $!;
        print $writeh "done\n";
        die("Failed to change perms on $home_dir: $err");
      }

      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->mdtm($test_file) };
      unless ($@) {
        print $writeh "done\n";
        die("MDTM succeeded unexpectedly");

      } else {
        $resp_code = $client->response_code();
        $resp_msg = $client->response_msg();
      }

      chmod($perms, $home_dir);

      my $expected;

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "$test_file: Permission denied";
      chomp($resp_msg);
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    print $writeh "done\n";

  } else {
    # Start server
    server_start($config_file);

    # Wait until we receive word from the child that it has finished its
    # test.
    while (my $msg = <$readh>) {
      chomp($msg);

      if ($msg eq 'done') {
        last;
      }
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
