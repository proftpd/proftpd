package ProFTPD::Tests::Config::MaxClients;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  maxclients_one => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  maxclients_one_ifsess_per_user_regex => {
    order => ++$order,
    test_class => [qw(forking mod_ifsession)],
  },

  maxclients_one_ifsess_sql_per_user_regex => {
    order => ++$order,
    test_class => [qw(forking mod_ifsession mod_sql mod_sql_sqlite)],
  },

  maxclients_one_anon_bug4068 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub maxclients_one {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'config');

  my $max_clients = 1;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    MaxClients => $max_clients,

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
      # First client should be able to connect and log in...
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($setup->{user}, $setup->{passwd});

      # ...but the second client should be able to connect, but not login.
      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      eval { $client2->login($setup->{user}, $setup->{passwd}) };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }

      $client1->quit();
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

  test_cleanup($setup, $ex);
}

sub maxclients_one_ifsess_per_user_regex {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'config');

  my $max_clients = 1;

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

  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<IfModule mod_ifsession.c>
  <IfUser regex ^$setup->{user}>
    MaxClients $max_clients
  </IfUser>
</IfModule>
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
      # First client should be able to connect and log in...
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($setup->{user}, $setup->{passwd});

      # ...but the second client should be able to connect, but not login.
      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      eval { $client2->login($setup->{user}, $setup->{passwd}) };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }

      $client1->quit();
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

  test_cleanup($setup, $ex);
}

sub maxclients_one_ifsess_sql_per_user_regex {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'config');

  my $db_file = File::Spec->rel2abs("$tmpdir/proftpd.db");

  # Build up sqlite3 command to create users, groups tables and populate them
  my $db_script = File::Spec->rel2abs("$tmpdir/proftpd.sql");

  if (open(my $fh, "> $db_script")) {
    print $fh <<EOS;
CREATE TABLE users (
  userid TEXT,
  passwd TEXT,
  uid INTEGER,
  gid INTEGER,
  homedir TEXT,
  shell TEXT,
  lastdir TEXT
);
INSERT INTO users (userid, passwd, uid, gid, homedir, shell) VALUES ('$setup->{user}', '$setup->{passwd}', $setup->{uid}, $setup->{gid}, '$setup->{home_dir}', '/bin/bash');

CREATE TABLE groups (
  groupname TEXT,
  gid INTEGER,
  members TEXT
);
INSERT INTO groups (groupname, gid, members) VALUES ('$setup->{group}', $setup->{gid}, '$setup->{user}');
EOS

    unless (close($fh)) {
      die("Can't write $db_script: $!");
    }

  } else {
    die("Can't open $db_script: $!");
  }

  my $cmd = "sqlite3 $db_file < $db_script";

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Executing sqlite3: $cmd\n";
  }

  my @output = `$cmd`;
  if (scalar(@output) &&
      $ENV{TEST_VERBOSE}) {
    print STDERR "Output: ", join('', @output), "\n";
  }

  my $max_clients = 1;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sql.c' => {
        AuthOrder => 'mod_sql.c',
        SQLAuthTypes => 'plaintext',
        SQLBackend => 'sqlite3',
        SQLConnectInfo => $db_file,
        SQLLogFile => $setup->{log_file},
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<IfModule mod_ifsession.c>
  <IfUser regex ^$setup->{user}>
    MaxClients $max_clients
  </IfUser>
</IfModule>
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
      # First client should be able to connect and log in...
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($setup->{user}, $setup->{passwd});

      # ...but the second client should be able to connect, but not login.
      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      eval { $client2->login($setup->{user}, $setup->{passwd}) };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }

      $client1->quit();
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

  test_cleanup($setup, $ex);
}

sub maxclients_one_anon_bug4068 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'config');

  my $max_clients = 1;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    Anonymous => {
      $setup->{home_dir} => {
        User => $setup->{user},
        Group => $setup->{group},
        UserAlias => "anonymous $setup->{user}",
        RequireValidShell => 'off',
        MaxClients => $max_clients,
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
      # First client should be able to connect and log in...
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($setup->{user}, 'ftp@nospam.org');

      # ...but the second client should be able to connect, but not login.
      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      eval { $client2->login($setup->{user}, 'ftp@nospam.org') };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }

      $client1->quit();
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

  test_cleanup($setup, $ex);
}

1;
