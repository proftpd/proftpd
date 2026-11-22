package ProFTPD::Tests::Modules::mod_ifsession;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use POSIX qw(:fcntl_h);

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  ifuser_allowoverwrite => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ifgroup_dir_allow_mkd_bug3467 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
  },

  ifuser_dir_allow_mkd_bug3467 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  ifclass_dir_allow_mkd_bug3467 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  ifuser_login_deny_by_ip => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ifuser_login_deny_by_user => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  ifgroup_ifclass_login_allowclass_bug3547 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  ifuser_regex_login_deny_by_ip_bug3625 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  ifauthenticated_bug3629 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  ifgroup_displaylogin_bug3882 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
  },

  ifgroup_dir_allow_stor_bug3881 => {
    order => ++$order,
    test_class => [qw(bug forking rootprivs)],
  },

  ifgroup_dir_allow_stor_bug3881_sftp => {
    order => ++$order,
    test_class => [qw(bug forking mod_sftp rootprivs)],
  },

  ifclass_global_no_logging => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  ifuser_no_pass_bug4199 => {
    order => ++$order,
    test_class => [qw(bug forking mod_tls)],
  },

  ifclass_and_not_classes => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  ifuser_directory_bug4315 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  ifsess_options_per_unauthenticated_user => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  ifsess_ftpaccess_closing_ctx => {
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

  my $rsa_host_key = File::Spec->rel2abs("t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("t/etc/modules/mod_sftp/ssh_host_dsa_key");

  unless (chmod(0400, $rsa_host_key, $dsa_host_key)) {
    die("Can't set perms on $rsa_host_key, $dsa_host_key: $!");
  }
}

sub ifuser_allowoverwrite {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

  my $ftpaccess_file = File::Spec->rel2abs("$tmpdir/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh "AllowOverwrite on\n";

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    close($fh);

  } else {
    die("Can't open $test_file: $!");
  }

  if ($< == 0) {
    unless (chown($setup->{uid}, $setup->{gid}, $test_file)) {
      die("Can't set owner of $test_file to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    AllowOverride => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<IfModule mod_ifsession.c>
  <IfUser $setup->{user}>
    AllowOverride on
  </IfUser>

  <IfUser !$setup->{user}>
    AllowOverride off
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("Failed to STOR test.txt: " . $client->response_code() . " " .
          $client->response_msg());
      }

      sleep(0.25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

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

  test_cleanup($setup, $ex);
}

sub ifgroup_dir_allow_mkd_bug3467 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

  my $user_dir = File::Spec->rel2abs("$setup->{home_dir}/$setup->{user}");
  mkpath($user_dir);

  my $ftpaccess_file = File::Spec->rel2abs("$user_dir/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh "Umask 022\n";

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  if ($< == 0) {
    unless (chmod(0755, $user_dir)) {
      die("Can't set perms on $user_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $user_dir)) {
      die("Can't set owner of $user_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    AllowOverride => 'on',
    DefaultRoot => "~ $setup->{group}",

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<Directory />
  <Limit ALL>
    DenyAll
  </Limit>
</Directory>

<IfGroup $setup->{group}>
  <Directory ~>
    <Limit ALL>
      AllowAll
    </Limit>
  </Directory>
</IfGroup>
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
      $client->mkd('foo');
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

  test_cleanup($setup, $ex);
}

sub ifuser_dir_allow_mkd_bug3467 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'directory:20',

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

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    my $limit_dir = $setup->{home_dir};
    if ($^O eq 'darwin') {
      # MacOSX hack
      $limit_dir = ('/private' . $setup->{home_dir});
    }

    print $fh <<EOC;
<Directory />
  <Limit ALL>
    DenyAll
  </Limit>
</Directory>

<IfUser $setup->{user}>
  <Directory $limit_dir>
    <Limit MKD>
      AllowAll
    </Limit>
  </Directory>
</IfUser>
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

      $client->mkd('foo');
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

  test_cleanup($setup, $ex);
}

sub ifclass_dir_allow_mkd_bug3467 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'directory:20',

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

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    my $limit_dir = $setup->{home_dir};
    if ($^O eq 'darwin') {
      $limit_dir = ('/private' . $setup->{home_dir});
    }

    print $fh <<EOC;
<Class local>
  From 127.0.0.1
</Class>

<Directory />
  <Limit ALL>
    DenyAll
  </Limit>
</Directory>

<IfClass local>
  <Directory $limit_dir>
    <Limit MKD>
      AllowAll
    </Limit>
  </Directory>
</IfClass>
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

      $client->mkd('foo');
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

  test_cleanup($setup, $ex);
}

sub ifuser_login_deny_by_ip  {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

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

  # Inspired by:
  #
  #  http://forums.proftpd.org/smf/index.php/topic,5153.0.html
  #
  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<IfModule mod_ifsession.c>
  <IfUser $setup->{user}>
    <Limit LOGIN>
      Deny from 127.0.0.1
    </Limit>
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      eval { $client->login($setup->{user}, $setup->{passwd}) };
      unless ($@) {
        die("Login succeeded unexpectedly");
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

  test_cleanup($setup, $ex);
}

sub ifuser_login_deny_by_user  {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

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
  <IfUser $setup->{user}>
    <Limit LOGIN>
      DenyUser $setup->{user}
    </Limit>
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      eval { $client->login($setup->{user}, $setup->{passwd}) };
      unless ($@) {
        die("Login succeeded unexpectedly");
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

  test_cleanup($setup, $ex);
}

sub ifgroup_ifclass_login_allowclass_bug3547 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

  my $test_group = 'test';
  my $test_gid = 501;

  auth_group_write($setup->{auth_group_file}, $test_group, $test_gid,
    $setup->{user});

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ifsession:20',

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
  <Class local>
    From 172.16.0.0/12
    From 192.168.0.0/16
  </Class>

  <Class test>
    From 127.0.0.1
  </Class>

  <IfGroup $test_group>
    <Limit LOGIN>
      AllowClass test
      AllowClass local
      DenyAll
    </Limit>
  </IfGroup>

  <IfGroup !$test_group>
    <Limit LOGIN>
      AllowClass local
      DenyAll
    </Limit>
  </IfGroup>
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

sub ifuser_regex_login_deny_by_ip_bug3625  {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

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
  <IfUser regex $setup->{user}>
    <Limit LOGIN>
      Deny from 127.0.0.1
    </Limit>
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      eval { $client->login($setup->{user}, $setup->{passwd}) };
      unless ($@) {
        die("Login succeeded unexpectedly");
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

  test_cleanup($setup, $ex);
}

sub ifauthenticated_bug3629 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    close($fh);

  } else {
    die("Can't open $test_file: $!");
  }

  if ($< == 0) {
    unless (chown($setup->{uid}, $setup->{gid}, $test_file)) {
      die("Can't set owner of $test_file to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'directory:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    my $limit_dir = $setup->{home_dir};
    if ($^O eq 'darwin') {
      # MacOSX hack
      $limit_dir = ('/private' . $setup->{home_dir});
    }

    print $fh <<EOC;
<Directory />
  <Limit WRITE>
    DenyAll
  </Limit>
</Directory>

<IfModule mod_ifsession.c>
  <IfAuthenticated>
    <Directory $limit_dir>
      <Limit WRITE>
        AllowAll
      </Limit>
    </Directory>
  </IfAuthenticated>
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

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("Failed to STOR test.txt: " . $client->response_code() . " " .
          $client->response_msg());
      }

      sleep(0.25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

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

  test_cleanup($setup, $ex);
}

sub ifgroup_displaylogin_bug3882 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

  my $login_file = File::Spec->rel2abs("$tmpdir/login.txt");
  if (open(my $fh, "> $login_file")) {
    print $fh "Hello user!\n";

    unless (close($fh)) {
      die("Unable to write $login_file: $!");
    }

  } else {
    die("Unable to open $login_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'auth:20 auth.file:20 fsio:20',

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

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<IfModule mod_ifsession.c>
  <IfGroup $setup->{group}>
    DisplayLogin $login_file
  </IfGroup>
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
      # Allow for server startup
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg(0);

      my $expected = 230;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Hello user!";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

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

  test_cleanup($setup, $ex);
}

sub ifgroup_dir_allow_stor_bug3881 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $uid = 500;
  my $gid = 500;
  my $home_dir = File::Spec->rel2abs("$tmpdir/users/$user");

  my $setup = test_setup($tmpdir, 'ifsess', $user, $passwd, $group, $uid,
    $gid, $home_dir);

  mkpath($home_dir);

  my $sub_dir = File::Spec->rel2abs("$setup->{home_dir}/test.d");
  mkpath($sub_dir);

  if ($^O eq 'darwin') {
    $home_dir = ('/private' . $home_dir);
  }

  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'directory:20 fileperms:10 ifsession:20',

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

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    my ($volume, $parent_dir, $file) = File::Spec->splitpath($home_dir);
    my $limit_dir = File::Spec->rel2abs("$parent_dir/*/test.d");
    if ($^O eq 'darwin') {
      # MacOSX hack
      $limit_dir = ('/private' . $limit_dir);
    }

    # XXX Hack, for now:
    $limit_dir = '~/test.d';

    print $fh <<EOC;
<Directory ~>
  <Limit WRITE>
    DenyAll
  </Limit>
</Directory>

<IfGroup $setup->{group}>
  <Directory $limit_dir>
    <Limit MKD XMKD RMD XRMD>
      DenyAll
    </Limit>

    <Limit WRITE>
      AllowAll
    </Limit>
  </Directory>
</IfGroup>
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
      $client->cwd('test.d');

      my $path = 'test.txt';
      my $conn = $client->stor_raw($path);
      unless ($conn) {
        die("Can't STOR $path: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      sleep(0.25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

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

  test_cleanup($setup, $ex);
}

sub ifgroup_dir_allow_stor_bug3881_sftp {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $uid = 500;
  my $gid = 500;
  my $home_dir = File::Spec->rel2abs("$tmpdir/users/$user");
  my $setup = test_setup($tmpdir, 'ifsess', $user, $passwd, $group, $uid,
    $gid, $home_dir);

  mkpath($home_dir);

  my $sub_dir = File::Spec->rel2abs("$home_dir/test.d");
  mkpath($sub_dir);

  if ($^O eq 'darwin') {
    $home_dir = ('/private' . $home_dir);
  }

  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  my $rsa_host_key = File::Spec->rel2abs("t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'directory:20 fileperms:10 ifsession:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    DefaultRoot => '~',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    my ($volume, $parent_dir, $file) = File::Spec->splitpath($home_dir);
    my $limit_dir = File::Spec->rel2abs("$parent_dir/*/test.d");
    if ($^O eq 'darwin') {
      # MacOSX hack
      $limit_dir = ('/private' . $limit_dir);
    }

    # XXX Hack, for now:
    $limit_dir = '~/test.d';

    print $fh <<EOC;
<Directory ~>
  <Limit WRITE>
    DenyAll
  </Limit>
</Directory>

<IfGroup $setup->{group}>
  <Directory $limit_dir>
    <Limit MKD XMKD RMD XRMD>
      DenyAll
    </Limit>

    <Limit WRITE>
      AllowAll
    </Limit>
  </Directory>
</IfGroup>
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

  require Net::SSH2;

  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
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

      my $path = 'test.d/test.txt';
      my $fh = $sftp->open($path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open $path: [$err_name] ($err_code)");
      }

      my $count = 20;
      for (my $i = 0; $i < $count; $i++) {
        print $fh "ABCD" x 8192;
      }

      # To issue the FXP_CLOSE, we have to explicitly destroy the filehandle
      $fh = undef;

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

  test_cleanup($setup, $ex);
}

# Regression test for issues described in:
#   https://forums.proftpd.org/smf/index.php/topic,11572.0.html
sub ifclass_global_no_logging {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

  my $ext_log = File::Spec->rel2abs("$tmpdir/ext.log");
  my $xfer_log = File::Spec->rel2abs("$tmpdir/xfer.log");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'directory:20 jot:20',

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

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    my $limit_dir = $setup->{home_dir};
    if ($^O eq 'darwin') {
      $limit_dir = ('/private' . $setup->{home_dir});
    }

    print $fh <<EOC;
ExtendedLog $ext_log ALL default
TransferLog $xfer_log

<Class local>
  From 127.0.0.1
</Class>

<Global>
  <IfClass local>
    ExtendedLog $ext_log NONE
    TransferLog none
  </IfClass>
</Global>
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
      $client->mkd('foo');
      $client->retr($setup->{config_file});
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
    if (open(my $fh, "< $ext_log")) {
      my $ok = 1;

      while (my $line = <$fh>) {
        chomp($line);
        $ok = 0;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }
      }
      close($fh);
      $self->assert($ok, test_msg("Saw ExtendedLog messages unexpectedly"));

    } else {
      die("Can't read $ext_log: $!");
    }

    if (open(my $fh, "< $xfer_log")) {
      close($fh);
      $self->assert(0, test_msg("Saw TransferLog unexpectedly"));
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub ifuser_no_pass_bug4199 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

  my $server_cert = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $client_cert = File::Spec->rel2abs('t/etc/modules/mod_tls/client-cert.pem');
  my $ca_cert = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $tlslogin_file = File::Spec->rel2abs("$tmpdir/.tlslogin");
  unless (copy($client_cert, $tlslogin_file)) {
    die("Can't copy $client_cert to $tlslogin_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'directory:20 tls:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $setup->{log_file},
        TLSRequired => 'on',
        TLSRSACertificateFile => $server_cert,
        TLSCACertificateFile => $ca_cert,
        TLSVerifyClient => 'on',

        TLSOptions => 'AllowDotLogin',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    my $limit_dir = $setup->{home_dir};
    if ($^O eq 'darwin') {
      # MacOSX hack
      $limit_dir = ('/private' . $setup->{home_dir});
    }

    print $fh <<EOC;
<Directory />
  <Limit ALL>
    DenyAll
  </Limit>
</Directory>

<IfUser $setup->{user}>
  <Directory $limit_dir>
    <Limit MKD>
      AllowAll
    </Limit>
  </Directory>
</IfUser>
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

  require Net::FTPSSL;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Give the server a chance to start up
      sleep(2);

      # Suppress annoying warning from IO::Socket::SSL.
      local $SIG{__WARN__} = sub {
        my $msg = shift;
        warn $msg unless $msg =~ /^Use of uninitialized value.*at .*IO\/Socket\/SSL\.pm/;
      };

      my $client_opts = {
        Croak => 1,
        Encryption => 'E',
        Port => $port,

        SSL_use_cert => 1,
        SSL_cert_file => $client_cert,
        SSL_key_file => $client_cert,
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
      };

      if ($ENV{TEST_VERBOSE}) {
        $client_opts->{Debug} = 1;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', $client_opts);
      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      unless ($client->_user($setup->{user})) {
        die("USER error: " . $client->last_message());
      }

      my $expected = "232 User $setup->{user} logged in";
      my $resp = $client->last_message();
      $self->assert($expected eq $resp,
        test_msg("Expected response '$expected', got '$resp'"));

      unless ($client->mkdir('foo')) {
        die("MKD error: " . $client->last_message());
      }

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

  test_cleanup($setup, $ex);
}

sub ifclass_and_not_classes {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'directory:20 ifsession:20',

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

  # Append the mod_ifsession config to the end of the config file
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<Class foo>
  From 1.2.3.4
</Class>

<Class bar>
  From 5.6.7.8
</Class>

<IfClass foo>
  AccessGrantMsg "FOO access granted for %u"
</IfClass>

<IfClass bar>
  AccessGrantMsg "BAR access granted for %u"
</IfClass>

<IfClass !foo AND !bar>
  AccessGrantMsg "OTHER access granted for %u"
</IfClass>
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
      my ($resp_code, $resp_msg) = $client->login($setup->{user}, $setup->{passwd});
      $client->quit();

      my $expected = '230';
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "OTHER access granted for $setup->{user}";
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

  test_cleanup($setup, $ex);
}

sub ifuser_directory_bug4315 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

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
  <IfUser $setup->{user}>
    <Directory />
      PathAllowFilter ^a
    </Directory>
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      eval { $client->mkd('bad') };
      unless ($@) {
        die("MKD /bad succeeded unexpectedly");
      }

      eval { $client->mkd('bad') };
      unless ($@) {
        die("MKD /bad succeeded unexpectedly");
      }

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

  test_cleanup($setup, $ex);
}

sub ifsess_options_per_unauthenticated_user {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ifsession:20',

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
  IfSessionOptions PerUnauthenticatedUser

  <IfUser $setup->{user}>
    <Limit LOGIN>
      DenyUser $setup->{user}
    </Limit>
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
      # Allow for server startup
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      eval { $client->login($setup->{user}, $setup->{passwd}) };
      unless ($@) {
        die("Login succeeded unexpectedly");
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

  test_cleanup($setup, $ex);
}

sub ifsess_ftpaccess_closing_ctx {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'ifsess');

  my $test_dir = File::Spec->rel2abs("$tmpdir/test.d");
  mkpath($test_dir);

  # We deliberately write an incomplete/unclosed config snippet here
  my $ftpaccess_file = File::Spec->rel2abs("$test_dir/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh <<EOC;
ServerAdmin MadeYouLook
</IfUser>
ServerAdmin MadeYouLookAgain
EOC
    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  if ($< == 0) {
    unless (chmod(0755, $test_dir)) {
      die("Can't set perms on $test_dir: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $test_dir)) {
      die("Can't set owner of $test_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    AllowOverride => 'on',

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      $client->cwd('test.d');
      my ($resp_code, $resp_msg) = $client->noop();
      $client->quit();

      my $expected = 200;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'NOOP command successful';
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /ServerAdmin: directive not allowed in \.ftpaccess context/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected log message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

1;
