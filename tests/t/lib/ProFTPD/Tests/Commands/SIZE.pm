package ProFTPD::Tests::Commands::SIZE;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Cwd;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  size_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  size_abs_symlink_file => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  # Rolled back per Bug#4332
  size_abs_symlink_file_chrooted_bug4219 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress rootprivs)],
  },

  size_rel_symlink_file => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  size_rel_symlink_file_chrooted_bug4219 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
  },

  size_abs_symlink_dir => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  # Rolled back per Bug#4332
  size_abs_symlink_dir_chrooted_bug4219 => {
    order => ++$order,
    test_class => [qw(bug forking inprogress rootprivs)],
  },

  size_rel_symlink_dir => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  size_rel_symlink_dir_chrooted_bug4219 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
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

sub size_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    close($fh);

  } else {
    die("Can't create $test_file: $!");
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('binary');

      my ($resp_code, $resp_msg) = $client->size($test_file);
      $client->quit();

      my $expected = 213;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 14;
      $self->assert($expected == $resp_msg,
        test_msg("Expected response message $expected, got $resp_msg"));
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

sub size_abs_symlink_file {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/sub.d");
  mkpath($sub_dir);

  my $test_file = File::Spec->rel2abs("$sub_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    close($fh);

  } else {
    die("Can't create $test_file: $!");
  }

  my $test_symlink = File::Spec->rel2abs("$sub_dir/test.lnk");

  my $dst_path = $test_file;
  if ($^O eq 'darwin') {
    # MacOSX-specific hack
    $dst_path = '/private' . $dst_path;
  }

  unless (symlink($dst_path, $test_symlink)) {
    die("Can't symlink $test_symlink to $dst_path: $!");
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('binary');

      my ($resp_code, $resp_msg) = $client->size('sub.d/test.lnk');
      $client->quit();

      my $expected = 213;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = -s $test_file;
      $self->assert($expected == $resp_msg,
        test_msg("Expected response message $expected, got $resp_msg"));
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

sub size_abs_symlink_file_chrooted_bug4219 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/sub.d");
  mkpath($sub_dir);

  my $test_file = File::Spec->rel2abs("$sub_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    close($fh);

  } else {
    die("Can't create $test_file: $!");
  }

  my $test_symlink = File::Spec->rel2abs("$sub_dir/test.lnk");

  my $dst_path = $test_file;
  if ($^O eq 'darwin') {
    # MacOSX-specific hack
    $dst_path = '/private' . $dst_path;
  }

  unless (symlink($dst_path, $test_symlink)) {
    die("Can't symlink $test_symlink to $dst_path: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DefaultRoot => '~',

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('binary');

      my ($resp_code, $resp_msg) = $client->size('sub.d/test.lnk');
      $client->quit();

      my $expected = 213;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = -s $test_file;
      $self->assert($expected == $resp_msg,
        test_msg("Expected response message $expected, got $resp_msg"));
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

sub size_rel_symlink_file {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/sub.d");
  mkpath($sub_dir);

  my $test_file = File::Spec->rel2abs("$sub_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    close($fh);

  } else {
    die("Can't create $test_file: $!");
  }

  my $cwd = getcwd();
  unless (chdir($sub_dir)) {
    die("Can't chdir to $tmpdir: $!");
  }

  unless (symlink('./test.txt', 'test.lnk')) {
    die("Can't symlink './test.txt' to 'test.lnk': $!");
  }

  unless (chdir($cwd)) {
    die("Can't chdir to $cwd: $!");
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('binary');

      my ($resp_code, $resp_msg) = $client->size('sub.d/test.lnk');
      $client->quit();

      my $expected = 213;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = -s $test_file;
      $self->assert($expected == $resp_msg,
        test_msg("Expected response message $expected, got $resp_msg"));
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

sub size_rel_symlink_file_chrooted_bug4219 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/sub.d");
  mkpath($sub_dir);

  my $test_file = File::Spec->rel2abs("$sub_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    close($fh);

  } else {
    die("Can't create $test_file: $!");
  }

  my $cwd = getcwd();
  unless (chdir($sub_dir)) {
    die("Can't chdir to $tmpdir: $!");
  }

  unless (symlink('./test.txt', 'test.lnk')) {
    die("Can't symlink './test.txt' to 'test.lnk': $!");
  }

  unless (chdir($cwd)) {
    die("Can't chdir to $cwd: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DefaultRoot => '~',

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('binary');

      my ($resp_code, $resp_msg) = $client->size('sub.d/test.lnk');
      $client->quit();

      my $expected = 213;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = -s $test_file;
      $self->assert($expected == $resp_msg,
        test_msg("Expected response message $expected, got $resp_msg"));
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

sub size_abs_symlink_dir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/sub.d");
  mkpath($sub_dir);

  my $test_dir = File::Spec->rel2abs("$sub_dir/test.d");
  mkpath($test_dir);

  my $test_symlink = File::Spec->rel2abs("$sub_dir/test.lnk");

  my $dst_path = $test_dir;
  if ($^O eq 'darwin') {
    $dst_path = '/private' . $dst_path;
  }

  unless (symlink($dst_path, $test_symlink)) {
    die("Can't symlink $test_symlink to $dst_path: $!");
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('binary');

      my $path = 'sub.d/test.lnk';
      eval { $client->size($path) };
      unless ($@) {
        die("SIZE test.lnk succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $client->quit();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$path: not a regular file";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message $expected, got $resp_msg"));
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

sub size_abs_symlink_dir_chrooted_bug4219 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/sub.d");
  mkpath($sub_dir);

  my $test_dir = File::Spec->rel2abs("$sub_dir/test.d");
  mkpath($test_dir);

  my $test_symlink = File::Spec->rel2abs("$sub_dir/test.lnk");

  my $dst_path = $test_dir;
  if ($^O eq 'darwin') {
    # MacOSX-specific hack
    $dst_path = '/private' . $dst_path;
  }

  unless (symlink($dst_path, $test_symlink)) {
    die("Can't symlink $test_symlink to $dst_path: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DefaultRoot => '~',

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('binary');

      my $path = 'sub.d/test.lnk';
      eval { $client->size($path) };
      unless ($@) {
        die("SIZE test.lnk succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $client->quit();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$path: not a regular file";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message $expected, got $resp_msg"));
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

sub size_rel_symlink_dir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/sub.d");
  mkpath($sub_dir);

  my $test_dir = File::Spec->rel2abs("$sub_dir/test.d");
  mkpath($test_dir);

  my $cwd = getcwd();
  unless (chdir($sub_dir)) {
    die("Can't chdir to $sub_dir: $!");
  }

  unless (symlink('./test.d', 'test.lnk')) {
    die("Can't symlink './test.d' to 'test.lnk': $!");
  }

  unless (chdir($cwd)) {
    die("Can't chdir to $cwd: $!");
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('binary');

      my $path = 'sub.d/test.lnk';
      eval { $client->size($path) };
      unless ($@) {
        die("SIZE test.lnk succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $client->quit();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$path: not a regular file";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message $expected, got $resp_msg"));
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

sub size_rel_symlink_dir_chrooted_bug4219 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/sub.d");
  mkpath($sub_dir);

  my $test_dir = File::Spec->rel2abs("$sub_dir/test.d");
  mkpath($test_dir);

  my $cwd = getcwd();
  unless (chdir($sub_dir)) {
    die("Can't chdir to $sub_dir: $!");
  }

  unless (symlink('./test.d', 'test.lnk')) {
    die("Can't symlink './test.d' to 'test.lnk': $!");
  }

  unless (chdir($cwd)) {
    die("Can't chdir to $cwd: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DefaultRoot => '~',

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('binary');

      my $path = 'sub.d/test.lnk';
      eval { $client->size($path) };
      unless ($@) {
        die("SIZE test.lnk succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $client->quit();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$path: not a regular file";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message $expected, got $resp_msg"));
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

sub size_fails_ascii {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    close($fh);

  } else {
    die("Can't open $test_file: $!");
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('ascii');

      eval { $client->size($test_file) };
      unless ($@) {
        die("SIZE succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $client->quit();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "SIZE not allowed in ASCII mode";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));
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

sub size_fails_enoent {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('binary');

      eval { $client->size($test_file) };
      unless ($@) {
        die("SIZE succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $client->quit();

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$test_file: No such file or directory";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));
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

sub size_fails_eperm {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'cmds');

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    close($fh);

  } else {
    die("Can't create $test_file: $!");
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('binary');

      # Make it such that perms on the home dir do not allow reads
      my $perms = (stat($setup->{home_dir}))[2];
      unless (chmod(0220, $setup->{home_dir})) {
        die("Failed to change perms on $setup->{home_dir}: $!");
      }

      eval { $client->size($test_file) };
      unless ($@) {
        die("SIZE succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $client->quit();

      chmod($perms, $setup->{home_dir});

      my $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "$test_file: Permission denied";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));
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
