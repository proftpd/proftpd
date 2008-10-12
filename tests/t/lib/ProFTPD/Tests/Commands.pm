package ProFTPD::Tests::Commands;

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
  cmds_pwd => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  cmds_xpwd => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  cmds_cwd => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  cmds_xcwd => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  cmds_cdup => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  cmds_xcup => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  cmds_syst => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  cmds_mkd => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  cmds_xmkd => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  cmds_rmd => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  cmds_xrmd => {
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

sub cmds_pwd {
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
        print $writeh "done\n";
        die("Failed to log in: $@");
      }

      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->pwd() };
      if ($@) {
        print $writeh "done\n";
        die("Failed to PWD: $@");
      }

      my $expected;

      $expected = 257;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "\"$home_dir\" is the current directory";
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

sub cmds_xpwd {
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
        print $writeh "done\n";
        die("Failed to log in: $@");
      }

      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->xpwd() };
      if ($@) {
        print $writeh "done\n";
        die("Failed to XPWD: $@");
      }

      my $expected;

      $expected = 257;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "\"$home_dir\" is the current directory";
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

sub cmds_cwd {
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

  my $sub_dir = File::Spec->rel2abs('tmp/foo');
  mkpath($sub_dir);
  
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
        print $writeh "done\n";
        die("Failed to log in: $@");
      }

      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->cwd($sub_dir) };
      if ($@) {
        print $writeh "done\n";
        die("Failed to CWD: $@");
      }

      my $expected;

      $expected = 250;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "CWD command successful";
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

sub cmds_xcwd {
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

  my $sub_dir = File::Spec->rel2abs('tmp/foo');
  mkpath($sub_dir);
  
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
        print $writeh "done\n";
        die("Failed to log in: $@");
      }

      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->xcwd($sub_dir) };
      if ($@) {
        print $writeh "done\n";
        die("Failed to XCWD: $@");
      }

      my $expected;

      $expected = 250;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "XCWD command successful";
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

sub cmds_cdup {
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
        print $writeh "done\n";
        die("Failed to log in: $@");
      }

      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->cdup() };
      if ($@) {
        print $writeh "done\n";
        die("Failed to CDUP: $@");
      }

      my $expected;

      $expected = 250;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "CDUP command successful";
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

sub cmds_xcup {
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
        print $writeh "done\n";
        die("Failed to log in: $@");
      }

      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->xcup() };
      if ($@) {
        print $writeh "done\n";
        die("Failed to XCUP: $@");
      }

      my $expected;

      $expected = 250;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "XCUP command successful";
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

sub cmds_syst {
  my $self = shift;

  my $config_file = 'tmp/cmds.conf';
  my $pid_file = File::Spec->rel2abs('tmp/cmds.pid');
  my $scoreboard_file = File::Spec->rel2abs('tmp/cmds.scoreboard');
  my $log_file = File::Spec->rel2abs('cmds.log');

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

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

      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->syst() };
      if ($@) {
        print $writeh "done\n";
        die("Failed to SYST: $@");
      }

      my $expected;

      $expected = 215;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "UNIX Type: L8";
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

sub cmds_mkd {
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

  my $sub_dir = File::Spec->rel2abs('tmp/foo');
  
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
        print $writeh "done\n";
        die("Failed to log in: $@");
      }

      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->mkd($sub_dir) };
      if ($@) {
        print $writeh "done\n";
        die("Failed to MKD: $@");
      }

      my $expected;

      $expected = 257;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "\"$sub_dir\" - Directory successfully created";
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

sub cmds_xmkd {
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

  my $sub_dir = File::Spec->rel2abs('tmp/foo');
  
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
        print $writeh "done\n";
        die("Failed to log in: $@");
      }

      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->xmkd($sub_dir) };
      if ($@) {
        print $writeh "done\n";
        die("Failed to XMKD: $@");
      }

      my $expected;

      $expected = 257;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "\"$sub_dir\" - Directory successfully created";
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

sub cmds_rmd {
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

  my $sub_dir = File::Spec->rel2abs('tmp/foo');
  mkpath($sub_dir);
  
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
        print $writeh "done\n";
        die("Failed to log in: $@");
      }

      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->rmd($sub_dir) };
      if ($@) {
        print $writeh "done\n";
        die("Failed to RMD: $@");
      }

      my $expected;

      $expected = 250;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "RMD command successful";
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

sub cmds_xrmd {
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

  my $sub_dir = File::Spec->rel2abs('tmp/foo');
  mkpath($sub_dir);
  
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
        print $writeh "done\n";
        die("Failed to log in: $@");
      }

      my ($resp_code, $resp_msg);
      eval { ($resp_code, $resp_msg) = $client->xrmd($sub_dir) };
      if ($@) {
        print $writeh "done\n";
        die("Failed to XRMD: $@");
      }

      my $expected;

      $expected = 250;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "XRMD command successful";
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
