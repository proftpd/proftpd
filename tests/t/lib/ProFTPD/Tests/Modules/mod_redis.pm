package ProFTPD::Tests::Modules::mod_redis;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use IO::Socket::INET6;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :features :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  redis_log_on_command => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  redis_log_on_command_custom_key => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  redis_log_on_command_per_dir => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  redis_log_on_command_per_dir_none => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  redis_log_on_command_per_dir_none2 => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  redis_log_on_event => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  redis_log_on_event_custom_key => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  redis_log_on_event_per_dir => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  redis_log_on_event_per_dir_none => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  redis_log_on_event_per_dir_none2 => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  redis_log_fmt_extra_with_log_on_command => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  redis_log_fmt_extra_with_log_on_event => {
    order => ++$order,
    test_class => [qw(forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  # Check for the required Perl modules:
  #
  #  Redis

  my $required = [qw(
    JSON
    Redis
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

sub get_redis_server {
  my $redis_server = '127.0.0.1';
  if (defined($ENV{REDIS_HOST})) {
    $redis_server = $ENV{REDIS_HOST};
  }

  return $redis_server;
}

sub redis_list_delete {
  my $key = shift;
  my $redis_server = get_redis_server();

  require Redis;
  my $redis = Redis->new(
    server => "$redis_server:6379",
    reconnect => 5,
    every => 250_000
  );

  $redis->del($key);
  $redis->quit();  
  return 1;
}

sub redis_list_getall {
  my $key = shift;
  my $redis_server = get_redis_server();

  require Redis;
  my $redis = Redis->new(
    server => "$redis_server:6379",
    reconnect => 5,
    every => 250_000
  );

  my $data = $redis->lrange($key, 0, -1);
  $redis->quit();

  return $data;
}

sub redis_log_on_command {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'redis');

  my $redis_server = get_redis_server();
  my $fmt_name = 'custom';
  redis_list_delete($fmt_name);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'jot:20 redis:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      # Note: we need to use arrays here, since order of directives matters.
      'mod_redis.c' => [
        'RedisEngine on',
        "RedisServer $redis_server:6379",
        "RedisLog $setup->{log_file}",
        "LogFormat $fmt_name \"%a %u\"",
        "RedisLogOnCommand PASS $fmt_name",
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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg(0);
      $client->quit();

      my $expected = 230;
      $self->assert($expected == $resp_code,
        "Expected response code $expected, got $resp_code");

      $expected = "User $setup->{user} logged in";
      $self->assert($expected eq $resp_msg,
        "Expected response message '$expected', got '$resp_msg'");
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
    my $data = redis_list_getall($fmt_name);

    if ($ENV{TEST_VERBOSE}) {
      use Data::Dumper;
      print STDERR "# Redis data: ", Dumper($data), "\n";
    }

    my $nrecords = scalar(@$data);
    $self->assert($nrecords == 1, "Expected 1 record, got $nrecords");

    require JSON;
    my $record = decode_json($data->[0]);

    my $expected = $setup->{user};
    $self->assert($record->{user} eq $expected,
      "Expected user '$expected', got '$record->{user}'");

    $expected = '127.0.0.1';
    $self->assert($record->{remote_ip} eq $expected,
      "Expected remote IP '$expected', got '$record->{remote_ip}'");
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub redis_log_on_command_custom_key {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'redis');

  my $redis_server = get_redis_server();
  my $fmt_name = 'custom';
  my $key_name = "ftp.$setup->{user}.PASS";
  redis_list_delete($key_name);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'jot:20 redis:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      # Note: we need to use arrays here, since order of directives matters.
      'mod_redis.c' => [
        'RedisEngine on',
        "RedisServer $redis_server:6379",
        "RedisLog $setup->{log_file}",
        "LogFormat $fmt_name \"%a %u\"",
        "RedisLogOnCommand PASS $fmt_name ftp.%u.%m",
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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg(0);
      $client->quit();

      my $expected = 230;
      $self->assert($expected == $resp_code,
        "Expected response code $expected, got $resp_code");

      $expected = "User $setup->{user} logged in";
      $self->assert($expected eq $resp_msg,
        "Expected response message '$expected', got '$resp_msg'");
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
    my $data = redis_list_getall($key_name);

    if ($ENV{TEST_VERBOSE}) {
      use Data::Dumper;
      print STDERR "# Redis data:\n", Dumper($data), "\n";
    }

    my $nrecords = scalar(@$data);
    $self->assert($nrecords == 1, "Expected 1 record, got $nrecords");

    require JSON;
    my $record = decode_json($data->[0]);

    my $expected = $setup->{user};
    $self->assert($record->{user} eq $expected,
      "Expected user '$expected', got '$record->{user}'");

    $expected = '127.0.0.1';
    $self->assert($record->{remote_ip} eq $expected,
      "Expected remote IP '$expected', got '$record->{remote_ip}'");
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub redis_log_on_command_per_dir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'redis');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/test.d");
  mkpath($sub_dir);

  my $redis_server = get_redis_server();
  my $fmt_name = 'custom';
  redis_list_delete($fmt_name);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'jot:20 redis:20',

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
    if ($^O eq 'darwin') {
      # Mac OSX hack
      $sub_dir = '/private' . $sub_dir;
    }

    print $fh <<EOC;
<IfModule mod_redis.c>
  RedisEngine on
  RedisServer $redis_server:6379
  RedisLog $setup->{log_file}
  LogFormat $fmt_name "%a %u"

  <Directory $sub_dir>
    RedisLogOnCommand PWD $fmt_name
  </Directory>
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->pwd();
      $client->cwd('test.d');
      $client->pwd();
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

  eval {
    my $data = redis_list_getall($fmt_name);

    if ($ENV{TEST_VERBOSE}) {
      use Data::Dumper;
      print STDERR "# Redis data:\n", Dumper($data), "\n";
    }

    my $nrecords = scalar(@$data);
    $self->assert($nrecords == 1, "Expected 1 record, got $nrecords");

    require JSON;
    my $record = decode_json($data->[0]);

    my $expected = $setup->{user};
    $self->assert($record->{user} eq $expected,
      "Expected user '$expected', got '$record->{user}'");

    $expected = '127.0.0.1';
    $self->assert($record->{remote_ip} eq $expected,
      "Expected remote IP '$expected', got '$record->{remote_ip}'");
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub redis_log_on_command_per_dir_none {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'redis');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/test.d");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the test dir has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chown($setup->{uid}, $setup->{gid}, $sub_dir)) {
      die("Can't set owner of $sub_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $redis_server = get_redis_server();
  my $fmt_name = 'custom';
  redis_list_delete($fmt_name);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'jot:20 redis:20',

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
    if ($^O eq 'darwin') {
      # Mac OSX hack
      $sub_dir = '/private' . $sub_dir;
    }

    print $fh <<EOC;
<IfModule mod_redis.c>
  RedisEngine on
  RedisServer $redis_server:6379
  RedisLog $setup->{log_file}
  LogFormat $fmt_name "%a %u"

  <Directory $setup->{home_dir}>
    RedisLogOnCommand PWD $fmt_name
  </Directory>

  <Directory $sub_dir>
    RedisLogOnCommand none
  </Directory>
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->pwd();
      $client->cwd('test.d');
      $client->pwd();
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

  eval {
    my $data = redis_list_getall($fmt_name);

    if ($ENV{TEST_VERBOSE}) {
      use Data::Dumper;
      print STDERR "# Redis data:\n", Dumper($data), "\n";
    }

    my $nrecords = scalar(@$data);
    $self->assert($nrecords == 1, "Expected 1 record, got $nrecords");
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub redis_log_on_command_per_dir_none2 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'redis');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/test.d");
  mkpath($sub_dir);

  my $redis_server = get_redis_server();
  my $fmt_name = 'custom';
  redis_list_delete($fmt_name);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'jot:20 redis:20',

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
    if ($^O eq 'darwin') {
      # Mac OSX hack
      $sub_dir = '/private' . $sub_dir;
    }

    print $fh <<EOC;
<IfModule mod_redis.c>
  RedisEngine on
  RedisServer $redis_server:6379
  RedisLog $setup->{log_file}
  LogFormat $fmt_name "%a %u"

  <Directory />
    RedisLogOnCommand PWD $fmt_name
  </Directory>

  <Directory $sub_dir>
    RedisLogOnCommand none
  </Directory>
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->pwd();
      $client->cwd('test.d');
      $client->pwd();
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

  eval {
    my $data = redis_list_getall($fmt_name);

    if ($ENV{TEST_VERBOSE}) {
      use Data::Dumper;
      print STDERR "# Redis data:\n", Dumper($data), "\n";
    }

    my $nrecords = scalar(@$data);
    $self->assert($nrecords == 1, "Expected 1 record, got $nrecords");
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub redis_log_on_event {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'redis');

  my $redis_server = get_redis_server();
  my $fmt_name = 'custom';
  redis_list_delete($fmt_name);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'event:20 netio:10 jot:20 redis:20 response:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      # Note: we need to use arrays here, since order of directives matters.
      'mod_redis.c' => [
        'RedisEngine on',
        "RedisServer $redis_server:6379",
        "RedisLog $setup->{log_file}",
        "LogFormat $fmt_name \"%A %a %b %c %D %d %E %{epoch} %F %f %{gid} %g %H %h %I %{iso8601} %J %L %l %m %O %P %p %{protocol} %R %r %{remote-port} %S %s %T %t %U %u %{uid} %V %v %{version}\"",
        "RedisLogOnEvent ALL $fmt_name",
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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg(0);

      my $expected = 230;
      $self->assert($expected == $resp_code,
        "Expected response code $expected, got $resp_code");

      $expected = "User $setup->{user} logged in";
      $self->assert($expected eq $resp_msg,
        "Expected response message '$expected', got '$resp_msg'");

      $client->quit();
      sleep(1);
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
    my $data = redis_list_getall($fmt_name);

    if ($ENV{TEST_VERBOSE}) {
      use Data::Dumper;
      print STDERR "# Redis data:\n", Dumper($data), "\n";
    }

    my $nrecords = scalar(@$data);
    $self->assert($nrecords == 4 || $nrecords == 5,
      "Expected 4-5 records, got $nrecords");

    require JSON;
    my $record = decode_json($data->[3]);

    my $expected = $setup->{user};
    $self->assert($record->{user} eq $expected,
      "Expected user '$expected', got '$record->{user}'");

    $expected = '127.0.0.1';
    $self->assert($record->{remote_ip} eq $expected,
      "Expected remote IP '$expected', got '$record->{remote_ip}'");
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub redis_log_on_event_custom_key {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'redis');

  my $redis_server = get_redis_server();
  my $fmt_name = 'custom';
  my $key_name = 'ftp.127.0.0.1';
  redis_list_delete($key_name);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'event:20 netio:10 jot:20 redis:20 response:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      # Note: we need to use arrays here, since order of directives matters.
      'mod_redis.c' => [
        'RedisEngine on',
        "RedisServer $redis_server:6379",
        "RedisLog $setup->{log_file}",
        "LogFormat $fmt_name \"%A %a %b %c %D %d %E %{epoch} %F %f %{gid} %g %H %h %I %{iso8601} %J %L %l %m %O %P %p %{protocol} %R %r %{remote-port} %S %s %T %t %U %u %{uid} %V %v %{version}\"",
        "RedisLogOnEvent ALL $fmt_name ftp.%a",
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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg(0);

      my $expected = 230;
      $self->assert($expected == $resp_code,
        "Expected response code $expected, got $resp_code");

      $expected = "User $setup->{user} logged in";
      $self->assert($expected eq $resp_msg,
        "Expected response message '$expected', got '$resp_msg'");

      $client->quit();
      sleep(1);
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
    my $data = redis_list_getall($key_name);

    if ($ENV{TEST_VERBOSE}) {
      use Data::Dumper;
      print STDERR "# Redis data:\n", Dumper($data), "\n";
    }

    my $nrecords = scalar(@$data);
    $self->assert($nrecords == 4 || $nrecords == 5,
      "Expected 4-5 records, got $nrecords");

    require JSON;
    my $record = decode_json($data->[3]);

    my $expected = $setup->{user};
    $self->assert($record->{user} eq $expected,
      "Expected user '$expected', got '$record->{user}'");

    $expected = '127.0.0.1';
    $self->assert($record->{remote_ip} eq $expected,
      "Expected remote IP '$expected', got '$record->{remote_ip}'");
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub redis_log_on_event_per_dir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'redis');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/test.d");
  mkpath($sub_dir);

  my $redis_server = get_redis_server();
  my $fmt_name = 'custom';
  redis_list_delete($fmt_name);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'jot:20 redis:20',

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
    if ($^O eq 'darwin') {
      # Mac OSX hack
      $sub_dir = '/private' . $sub_dir;
    }

    print $fh <<EOC;
<IfModule mod_redis.c>
  RedisEngine on
  RedisServer $redis_server:6379
  RedisLog $setup->{log_file}
  LogFormat $fmt_name "%a %u"

  <Directory $sub_dir>
    RedisLogOnEvent PWD $fmt_name
  </Directory>
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->pwd();
      $client->cwd('test.d');
      $client->pwd();
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

  eval {
    my $data = redis_list_getall($fmt_name);

    if ($ENV{TEST_VERBOSE}) {
      use Data::Dumper;
      print STDERR "# Redis data:\n", Dumper($data), "\n";
    }

    my $nrecords = scalar(@$data);
    $self->assert($nrecords == 1, "Expected 1 record, got $nrecords");

    require JSON;
    my $record = decode_json($data->[0]);

    my $expected = $setup->{user};
    $self->assert($record->{user} eq $expected,
      "Expected user '$expected', got '$record->{user}'");

    $expected = '127.0.0.1';
    $self->assert($record->{remote_ip} eq $expected,
      "Expected remote IP '$expected', got '$record->{remote_ip}'");
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub redis_log_on_event_per_dir_none {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'redis');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/test.d");
  mkpath($sub_dir);

  my $redis_server = get_redis_server();
  my $fmt_name = 'custom';
  redis_list_delete($fmt_name);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'jot:20 redis:20',

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
    if ($^O eq 'darwin') {
      # Mac OSX hack
      $sub_dir = '/private' . $sub_dir;
    }

    print $fh <<EOC;
<IfModule mod_redis.c>
  RedisEngine on
  RedisServer $redis_server:6379
  RedisLog $setup->{log_file}
  LogFormat $fmt_name "%a %u"

  <Directory $setup->{home_dir}>
    RedisLogOnEvent PWD $fmt_name
  </Directory>

  <Directory $sub_dir>
    RedisLogOnEvent none
  </Directory>
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->pwd();
      $client->cwd('test.d');
      $client->pwd();
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

  eval {
    my $data = redis_list_getall($fmt_name);

    if ($ENV{TEST_VERBOSE}) {
      use Data::Dumper;
      print STDERR "# Redis data:\n", Dumper($data), "\n";
    }

    my $nrecords = scalar(@$data);
    $self->assert($nrecords == 1, "Expected 1 record, got $nrecords");
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub redis_log_on_event_per_dir_none2 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'redis');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/test.d");
  mkpath($sub_dir);

  my $redis_server = get_redis_server();
  my $fmt_name = 'custom';
  redis_list_delete($fmt_name);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'jot:20 redis:20',

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
    if ($^O eq 'darwin') {
      # Mac OSX hack
      $sub_dir = '/private' . $sub_dir;
    }

    print $fh <<EOC;
<IfModule mod_redis.c>
  RedisEngine on
  RedisServer $redis_server:6379
  RedisLog $setup->{log_file}
  LogFormat $fmt_name "%a %u"

  <Directory />
    RedisLogOnEvent PWD $fmt_name
  </Directory>

  <Directory $sub_dir>
    RedisLogOnEvent none
  </Directory>
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->pwd();
      $client->cwd('test.d');
      $client->pwd();
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

  eval {
    my $data = redis_list_getall($fmt_name);

    if ($ENV{TEST_VERBOSE}) {
      use Data::Dumper;
      print STDERR "# Redis data:\n", Dumper($data), "\n";
    }

    my $nrecords = scalar(@$data);
    $self->assert($nrecords == 1, "Expected 1 record, got $nrecords");
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub redis_log_fmt_extra_with_log_on_command {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'redis');

  my $redis_server = get_redis_server();
  my $fmt_name = 'custom';
  redis_list_delete($fmt_name);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'jot:20 redis:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      # Note: we need to use arrays here, since order of directives matters.
      'mod_redis.c' => [
        'RedisEngine on',
        "RedisServer $redis_server:6379",
        "RedisLog $setup->{log_file}",
        "LogFormat $fmt_name \"%a %u\"",
        "RedisLogOnCommand PASS $fmt_name",
        "RedisLogFormatExtra $fmt_name {\"foo\":\"%u\",\"bar\":\"BAZ\",\"baz\":{},\"quxx\":[1,3,5],\"quzz\":null}",
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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg(0);
      $client->quit();

      my $expected = 230;
      $self->assert($expected == $resp_code,
        "Expected response code $expected, got $resp_code");

      $expected = "User $setup->{user} logged in";
      $self->assert($expected eq $resp_msg,
        "Expected response message '$expected', got '$resp_msg'");
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
    my $data = redis_list_getall($fmt_name);

    my $nrecords = scalar(@$data);
    $self->assert($nrecords == 1, "Expected 1 record, got $nrecords");

    require JSON;
    my $record = decode_json($data->[0]);

    my $expected = $setup->{user};
    $self->assert($record->{user} eq $expected,
      "Expected user '$expected', got '$record->{user}'");

    $expected = '127.0.0.1';
    $self->assert($record->{remote_ip} eq $expected,
      "Expected remote IP '$expected', got '$record->{remote_ip}'");

    # Note that we do not expect the "quzz" key, because it is null.
    foreach my $key (qw(foo bar baz quxx)) {
      $self->assert(defined($record->{$key}),
        "Key $key does not exist in record as expected");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub redis_log_fmt_extra_with_log_on_event {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'redis');

  my $redis_server = get_redis_server();
  my $fmt_name = 'custom';
  redis_list_delete($fmt_name);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'jot:20 redis:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      # Note: we need to use arrays here, since order of directives matters.

      # Note: we need to use arrays here, since order of directives matters.
      'mod_redis.c' => [
        'RedisEngine on',
        "RedisServer $redis_server:6379",
        "RedisLog $setup->{log_file}",
        "LogFormat $fmt_name \"%A %a %b %c %D %d %E %{epoch} %F %f %{gid} %g %H %h %I %{iso8601} %J %L %l %m %O %P %p %{protocol} %R %r %{remote-port} %S %s %T %t %U %u %{uid} %V %v %{version}\"",
        "RedisLogOnEvent ALL $fmt_name",
        "RedisLogFormatExtra $fmt_name {\"foo\":\"%u\",\"bar\":\"BAZ\",\"baz\":{},\"quxx\":[1,3,5],\"quzz\":null}",
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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg(0);
      $client->quit();
      sleep(1);

      my $expected = 230;
      $self->assert($expected == $resp_code,
        "Expected response code $expected, got $resp_code");

      $expected = "User $setup->{user} logged in";
      $self->assert($expected eq $resp_msg,
        "Expected response message '$expected', got '$resp_msg'");
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
    my $data = redis_list_getall($fmt_name);

    my $nrecords = scalar(@$data);
    $self->assert($nrecords == 4 || $nrecords == 5,
      "Expected 4-5 records, got $nrecords");

    require JSON;
    my $record = decode_json($data->[3]);

    my $expected = $setup->{user};
    $self->assert($record->{user} eq $expected,
      "Expected user '$expected', got '$record->{user}'");

    $expected = '127.0.0.1';
    $self->assert($record->{remote_ip} eq $expected,
      "Expected remote IP '$expected', got '$record->{remote_ip}'");

    # Note that we do not expect the "quzz" key, because it is null.
    foreach my $key (qw(foo bar baz quxx)) {
      $self->assert(defined($record->{$key}),
        "Key $key does not exist in record as expected");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

1;
