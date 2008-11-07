package ProFTPD::Tests::Modules::mod_sql_sqlite;

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
  sql_bug2922 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
  },

  sql_bug3116 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  sql_bug3124 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  sql_sqlite_bug3126 => {
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

sub sql_bug2922 {
  my $self = shift;

  my $config_file = 'tmp/sqlite.conf';
  my $pid_file = File::Spec->rel2abs('tmp/sqlite.pid');
  my $scoreboard_file = File::Spec->rel2abs('tmp/sqlite.scoreboard');
  my $log_file = File::Spec->rel2abs('sqlite.log');
  my $sql_log_file = File::Spec->rel2abs('sql.log');

  # Bug#2922 occurred because mod_sql would "authenticate" the plaintext
  # password (if configured to do so) of a user whose info did NOT come from
  # mod_sql.

  my $db_file = File::Spec->rel2abs('tmp/proftpd.db');

  # Build up sqlite3 command to create users, groups tables and populate them
  my $db_script = File::Spec->rel2abs('tmp/proftpd.sql');

  if (open(my $fh, "> $db_script")) {
    print $fh <<EOS;
CREATE TABLE users (
  userid TEXT,
  passwd TEXT,
  uid INTEGER,
  gid INTEGER,
  homedir TEXT, 
  shell TEXT
);

CREATE TABLE groups (
  groupname TEXT,
  gid INTEGER,
  members TEXT
);
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

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    MaxLoginAttempts => 100,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sql.c' => {
        SQLAuthTypes => 'plaintext',
        SQLBackend => 'sqlite3',
        SQLConnectInfo => $db_file,
        SQLLogFile => $sql_log_file,
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
      # Bug#2922 would allow a login which should NOT happen.  So if
      # *any* of the following logins succeed, we have a problem.

      my $accounts = [
        { user => 'bin', passwd => '*' },
        { user => 'bin', passwd => 'x' },
        { user => 'daemon', passwd => '*' },
        { user => 'daemon', passwd => 'x' },
        { user => 'mysql', passwd => '*' },
        { user => 'mysql', passwd => 'x' },
      ];

      foreach my $account (@$accounts) {
        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
        my $user = $account->{user};
        my $passwd = $account->{passwd};

        eval { $client->login($user, $passwd) };
        unless ($@) {
          die("Logged in unexpectedly");
        }
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

  unlink($log_file);
  unlink($sql_log_file);
}

sub sql_bug3116 {
  my $self = shift;

  my $config_file = 'tmp/sqlite.conf';
  my $pid_file = File::Spec->rel2abs('tmp/sqlite.pid');
  my $scoreboard_file = File::Spec->rel2abs('tmp/sqlite.scoreboard');
  my $log_file = File::Spec->rel2abs('sqlite.log');
  my $sql_log_file = File::Spec->rel2abs('sql.log');

  # Bug#3116 occurred because mod_sql was treating percent signs in user
  # (and group) names as variables to be substituted.

  my $user = 'proftpd%proftpd.org';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs('tmp');

  my $db_file = File::Spec->rel2abs('tmp/proftpd.db');

  # Build up sqlite3 command to create users, groups tables and populate them
  my $db_script = File::Spec->rel2abs('tmp/proftpd.sql');

  if (open(my $fh, "> $db_script")) {
    print $fh <<EOS;
CREATE TABLE users (
  userid TEXT,
  passwd TEXT,
  uid INTEGER,
  gid INTEGER,
  homedir TEXT, 
  shell TEXT
);
INSERT INTO users (userid, passwd, uid, gid, homedir, shell) VALUES ('$user', '$passwd', 500, 500, '$home_dir', 'bin/bash');

CREATE TABLE groups (
  groupname TEXT,
  gid INTEGER,
  members TEXT
);
INSERT INTO groups (groupname, gid, members) VALUES ('ftpd', 500, '$user');
INSERT INTO groups (groupname, gid, members) VALUES ('ftpadm', 501, '$user');
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

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sql.c' => {
        SQLAuthTypes => 'plaintext',
        SQLBackend => 'sqlite3',
        SQLConnectInfo => $db_file,
        SQLLogFile => $sql_log_file,
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

      # Bug#3116 would prevent a login from occurring, so we only need to
      # attempt a login.
      $client->login($user, $passwd, 5);
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
  unlink($sql_log_file);
}

sub sql_bug3124 {
  my $self = shift;

  my $config_file = 'tmp/sqlite.conf';
  my $pid_file = File::Spec->rel2abs('tmp/sqlite.pid');
  my $scoreboard_file = File::Spec->rel2abs('tmp/sqlite.scoreboard');
  my $log_file = File::Spec->rel2abs('sqlite.log');
  my $sql_log_file = File::Spec->rel2abs('sql.log');

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs('tmp');

  my $db_file = File::Spec->rel2abs('tmp/proftpd.db');

  # Build up sqlite3 command to create users, groups tables and populate them
  my $db_script = File::Spec->rel2abs('tmp/proftpd.sql');

  if (open(my $fh, "> $db_script")) {
    print $fh <<EOS;
CREATE TABLE users (
  userid TEXT,
  passwd TEXT,
  uid INTEGER,
  gid INTEGER,
  homedir TEXT, 
  shell TEXT
);
INSERT INTO users (userid, passwd, uid, gid, homedir, shell) VALUES ('$user', '$passwd', 500, 500, '$home_dir', 'bin/bash');

CREATE TABLE groups (
  groupname TEXT,
  gid INTEGER,
  members TEXT
);
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

  # Bug#3124 occurred when SQLNegativeCache was on, and there was no group
  # info; it would cause a segfault.

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sql.c' => {
        SQLAuthTypes => 'plaintext',
        SQLBackend => 'sqlite3',
        SQLConnectInfo => $db_file,
        SQLLogFile => $sql_log_file,
        SQLNegativeCache => 'on',
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

      # Bug#3124 would prevent a login from occurring, so we only need to
      # attempt a login.
      $client->login($user, $passwd, 5);
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
  unlink($sql_log_file);
}

sub sql_sqlite_bug3126 {
  my $self = shift;

  my $config_file = 'tmp/sqlite.conf';
  my $pid_file = File::Spec->rel2abs('tmp/sqlite.pid');
  my $scoreboard_file = File::Spec->rel2abs('tmp/sqlite.scoreboard');
  my $log_file = File::Spec->rel2abs('sqlite.log');
  my $sql_log_file = File::Spec->rel2abs('sql.log');

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs('tmp');

  my $db_file = File::Spec->rel2abs('tmp/proftpd.db');

  # Build up sqlite3 command to create users, groups tables and populate them
  my $db_script = File::Spec->rel2abs('tmp/proftpd.sql');

  if (open(my $fh, "> $db_script")) {
    print $fh <<EOS;
CREATE TABLE users (
  userid TEXT,
  passwd TEXT,
  uid INTEGER,
  gid INTEGER,
  homedir TEXT, 
  shell TEXT
);
INSERT INTO users (userid, passwd, uid, gid, homedir, shell) VALUES ('$user', '$passwd', 500, 500, '$home_dir', 'bin/bash');

CREATE TABLE groups (
  groupname TEXT,
  gid INTEGER,
  members TEXT
);
INSERT INTO groups (groupname, gid, members) VALUES ('ftpd', 500, '$user');
INSERT INTO groups (groupname, gid, members) VALUES ('ftpadm', 501, '$user');
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

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sql.c' => {
        SQLAuthTypes => 'plaintext',
        SQLBackend => 'sqlite3',
        SQLConnectInfo => $db_file,
        SQLLogFile => $sql_log_file,
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

      # Bug#3126 would prevent a login from occurring, so we only need to
      # attempt a login.
      $client->login($user, $passwd, 5);
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
  unlink($sql_log_file);
}

1;
