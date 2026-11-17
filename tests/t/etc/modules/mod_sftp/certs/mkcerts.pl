#!/usr/bin/env perl

use strict;

use File::Spec;

my $serialno = 1;

my $host_ca_keys = {
  'RSA' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_key",
  'ECDSA256' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa256_ca_key",
  'ECDSA384' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa384_ca_key",
  'ECDSA521' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa521_ca_key",
  'ED25519' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ed25519_ca_key",
};

my $user_ca_keys = {
  'RSA' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_user_rsa_ca_key",
  'ECDSA256' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_user_ecdsa256_ca_key",
  'ECDSA384' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_user_ecdsa384_ca_key",
  'ECDSA521' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_user_ecdsa521_ca_key",
  'ED25519' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_user_ed25519_ca_key",
};

my $public_keys = {
  'RSA' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub",
  'ECDSA256' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa256_key.pub",
  'ECDSA384' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa384_key.pub",
  'ECDSA521' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa521_key.pub",
  'ED25519' => "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_openssh_ed25519_key.pub",
};

foreach my $ca_algo (keys(%$user_ca_keys)) {
  my $ca_key = $user_ca_keys->{$ca_algo};

  # OpenSSH is understandably picky about permissions on these CA keys.
  unless (chmod(0600, $ca_key)) {
    die("Can't set perms on $ca_key: $!");
  }

  foreach my $algo (keys(%$public_keys)) {
    my $comment = "mod_sftp test $algo user cert";
    my $principal = 'proftpd';
    my $pub_key = $public_keys->{$algo};
    my $cert = "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/user_" . lc($ca_algo) . '_ca_' . lc($algo) . '_cert.pub';

    make_cert($ca_key, $comment, $principal, $serialno++, $pub_key, $cert, 0);
  }

  unless (chmod(644, $ca_key)) {
    die("Can't restore perms on $ca_key: $!");
  }
}

foreach my $ca_algo (keys(%$host_ca_keys)) {
  my $ca_key = $host_ca_keys->{$ca_algo};

  # OpenSSH is understandably picky about permissions on these CA keys.
  unless (chmod(0600, $ca_key)) {
    die("Can't set perms on $ca_key: $!");
  }

  foreach my $algo (keys(%$public_keys)) {
    my $comment = "mod_sftp test $algo host cert";
    my $principal = '127.0.0.1';
    my $pub_key = $public_keys->{$algo};
    my $cert = "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_" . lc($ca_algo) . '_ca_' . lc($algo) . '_cert.pub';

    make_cert($ca_key, $comment, $principal, $serialno++, $pub_key, $cert, 1);
  }

  unless (chmod(644, $ca_key)) {
    die("Can't restore perms on $ca_key: $!");
  }
}

# And now for the one-off special certs, for testing configurations and
# edge cases.

my $ca_key = $user_ca_keys->{RSA};
unless (chmod(0600, $ca_key)) {
  die("Can't set perms on $ca_key: $!");
}

make_cert($ca_key, 'mod_sftp test RSA user cert with AllowMatchPrincipals',
  'pr?ftp*', $serialno++, $public_keys->{RSA},
  "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/user_rsa_ca_rsa_cert_match_principals.pub", 0);

unless (chmod(0644, $ca_key)) {
  die("Can't restore perms on $ca_key: $!");
}

$ca_key = $host_ca_keys->{RSA};
unless (chmod(0600, $ca_key)) {
  die("Can't set perms on $ca_key: $!");
}

make_cert($ca_key, 'mod_sftp test RSA host cert with AllowMatchPrincipals',
  '127.?.?.*,l?calh*', $serialno++, $public_keys->{RSA},
  "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_rsa_ca_rsa_cert_match_principals.pub", 1);

make_cert($ca_key, 'mod_sftp test RSA host cert with AllowEmptyPrincipals',
  undef, $serialno++, $public_keys->{RSA},
  "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_rsa_ca_rsa_cert_empty_principals.pub", 1);

unless (chmod(0644, $ca_key)) {
  die("Can't restore perms on $ca_key: $!");
}

exit 0;

# ------
sub exec_cmd {
  my $cmd = shift;

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Executing command: $cmd\n";
  }

  my $quiet = '> /dev/null 2>&1';
  if ($ENV{TEST_VERBOSE}) {
    $quiet = '';
  }

  my @output = `$cmd $quiet`;
  my $exit_status = $?;

  if ($ENV{TEST_VERBOSE}) {
    if (scalar(@output) > 0) {
      print STDERR "# Output: ", join('', @output), "\n";
    }
  }

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Exit status: $exit_status\n";
  }

  if ($exit_status != 0) {
    print STDERR "# Command '$cmd' FAILED\n";
  }
}

sub make_cert {
  my $ca_key_file = shift;
  my $comment = shift;
  my $principal = shift;
  my $cert_serialno = shift;
  my $pub_key_file = shift;
  my $cert_file = shift;
  my $is_host_cert = shift;
  $is_host_cert = 0 unless defined($is_host_cert);

  my $verbose = '';
  if ($ENV{TEST_VERBOSE}) {
    $verbose = '-vvv';
  }

  my $cert_type = '';
  if ($is_host_cert) {
    $cert_type = '-h';
  }

  # There is at least one case where we deliberately want to omit any
  # principals from the generated cert, for testing.
  my $principals = '';
  if (defined($principal)) {
    $principals = "-n '$principal'";
  }

  my $cmd = "ssh-keygen $verbose -s $ca_key_file -I '$comment' $cert_type $principals -V +1h -z $cert_serialno $pub_key_file";
  exec_cmd($cmd);

  # ssh-keygen automatically names the generated certificate file based on
  # the provided key, so we compute that expected file name in order to
  # move/rename it to where we really want it to be.
  my $output_file = $pub_key_file;
  $output_file =~ s/\.pub$//;
  $output_file .= '-cert.pub';

  $cmd = "mv $output_file $cert_file";
  exec_cmd($cmd);
}
