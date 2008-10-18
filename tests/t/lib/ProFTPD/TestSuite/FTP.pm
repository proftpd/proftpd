package ProFTPD::TestSuite::FTP;

use strict;

use Carp;
use Net::FTP;
use POSIX qw(:sys_wait_h);

sub new {
  my $class = shift;
  my ($addr, $port, $use_pasv, $timeout) = @_;
  $use_pasv = 0 unless defined($use_pasv);
  $timeout = 10 unless defined($timeout);
 
  my $ftp;

  my $now = time();

  # Creating a Net::FTP object involves attempting to connect to the given
  # address/port.  So handle the test cases where the server process may
  # not yet be completely up, retry this connect, once a second, up to the
  # given timeout.

  my %opts = (
      Host => $addr,
      Port => $port,
  );

  if ($use_pasv) {
    $opts{Passive} = 1;

  } else {
    $opts{Passive} = 0;
  }

  if ($ENV{TEST_VERBOSE}) {
    $opts{Debug} = 10;
  }

  while (1) {
    if (time() - $now > $timeout) {
      croak("Unable to connect to $addr:$port: Timed out after $timeout secs");
    }

    $ftp = Net::FTP->new(%opts);

    last if $ftp;
    sleep(1);
  }

  my $self = {
    addr => $addr,
    ftp => $ftp,
    port => $port,
  };

  bless($self, $class);
  return $self;
}

sub response_code {
  my $self = shift;
  return $self->{ftp}->code;
}

sub response_msg {
  my $self = shift;
  if (defined($self->{mesg})) {
    my $msg = $self->{mesg};
    delete($self->{mesg});
    chomp($msg);
    return $msg;
  }

  my @msgs = $self->{ftp}->message;
  if (scalar(@msgs) > 1) {
    chomp($msgs[1]);
    return $msgs[1];
  }

  chomp($msgs[0]);
  return $msgs[0];
}

sub response_uniq {
  my $self = shift;

  my $uniq;
  if (defined($self->{uniq})) {
    $uniq = $self->{uniq};
    delete($self->{uniq});

  } else {
    $uniq = $self->{ftp}->unique_name();
    unless ($uniq) {
      my @msgs = $self->{ftp}->message;
      if (scalar(@msgs) > 1) {
        my $tmp = $msgs[0];

        if ($tmp =~ /^FILE:\s+(\S+)$/) {
          $uniq = $1;
        }
      }
    }
  }

  chomp($uniq);
  return $uniq;
}

sub login {
  my $self = shift;
  my $user = shift;
  croak("Missing required user argument") unless $user;
  my $pass = shift;
  croak("Missing required password argument") unless $pass;

  unless ($self->{ftp}->login($user, $pass)) {
    croak("Failed to login to $self->{addr}:$self->{port}: " .
      $self->{ftp}->code . ' ' . $self->{ftp}->message);
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub pwd {
  my $self = shift;

  unless ($self->{ftp}->pwd()) {
    croak("PWD command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub xpwd {
  my $self = shift;
  my $code;

  $code = $self->{ftp}->quot('XPWD');
  unless ($code) {
    croak("XPWD command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  if ($code == 4 || $code == 5) {
    croak("XPWD command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub cwd {
  my $self = shift;
  my $dir = shift;

  unless ($self->{ftp}->cwd($dir)) {
    croak("CWD command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub xcwd {
  my $self = shift;
  my $dir = shift;
  my $code;

  $code = $self->{ftp}->quot('XCWD', $dir);
  unless ($code) {
    croak("XCWD command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  if ($code == 4 || $code == 5) {
    croak("XCWD command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub cdup {
  my $self = shift;
  my $dir = shift;

  unless ($self->{ftp}->cdup()) {
    croak("CDUP command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub xcup {
  my $self = shift;
  my $code;

  $code = $self->{ftp}->quot('XCUP');
  unless ($code) {
    croak("XCUP command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  if ($code == 4 || $code == 5) {
    croak("XCUP command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub syst {
  my $self = shift;
  my $code;

  $code = $self->{ftp}->quot('SYST');
  unless ($code) {
    croak("SYST command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  if ($code == 4 || $code == 5) {
    croak("SYST command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub mkd {
  my $self = shift;
  my $dir = shift;

  unless ($self->{ftp}->mkdir($dir)) {
    croak("MKD command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub xmkd {
  my $self = shift;
  my $dir = shift;
  my $code;

  $code = $self->{ftp}->quot('XMKD', $dir);
  unless ($code) {
    croak("XMKD command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  if ($code == 4 || $code == 5) {
    croak("XMKD command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub rmd {
  my $self = shift;
  my $dir = shift;

  unless ($self->{ftp}->rmdir($dir)) {
    croak("RMD command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub xrmd {
  my $self = shift;
  my $dir = shift;
  my $code;

  $code = $self->{ftp}->quot('XRMD', $dir);
  unless ($code) {
    croak("XRMD command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  if ($code == 4 || $code == 5) {
    croak("XRMD command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub dele {
  my $self = shift;
  my $path = shift;

  unless ($self->{ftp}->delete($path)) {
    croak("DELE command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub type {
  my $self = shift;
  my $type = shift;

  if ($type =~ /^ascii$/i) {
    unless ($self->{ftp}->ascii()) {
      croak("TYPE command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

  } elsif ($type =~ /^binary$/i) {
    unless ($self->{ftp}->binary()) {
      croak("TYPE command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

  } else {
    my $code;

    $code = $self->{ftp}->quot('TYPE', $type);
    unless ($code) {
      croak("TYPE command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

    if ($code == 4 || $code == 5) {
      croak("TYPE command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub mdtm {
  my $self = shift;
  my $path = shift;

  unless ($self->{ftp}->mdtm($path)) {
    croak("MDTM command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub size {
  my $self = shift;
  my $path = shift;

  unless ($self->{ftp}->size($path)) {
    croak("SIZE command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub pasv {
  my $self = shift;

  unless ($self->{ftp}->pasv()) {
    croak("PASV command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub port {
  my $self = shift;
  my $port = shift;

  unless ($self->{ftp}->port($port)) {
    croak("PORT command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub mode {
  my $self = shift;
  my $mode = shift;

  if ($mode =~ /^stream$/i) {
    my $code;

    $code = $self->{ftp}->quot('MODE', 'S');
    unless ($code) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

    if ($code == 4 || $code == 5) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

  } elsif ($mode =~ /^block$/i) {
    my $code;

    $code = $self->{ftp}->quot('MODE', 'B');
    unless ($code) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

    if ($code == 4 || $code == 5) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

  } elsif ($mode =~ /^compress(ed)?$/i) {
    my $code;

    $code = $self->{ftp}->quot('MODE', 'C');
    unless ($code) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

    if ($code == 4 || $code == 5) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

  } else {
    my $code;

    $code = $self->{ftp}->quot('MODE', $mode);
    unless ($code) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

    if ($code == 4 || $code == 5) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub stru {
  my $self = shift;
  my $stru = shift;

  if ($stru =~ /^file$/i) {
    my $code;

    $code = $self->{ftp}->quot('STRU', 'F');
    unless ($code) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

    if ($code == 4 || $code == 5) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

  } elsif ($stru =~ /^record$/i) {
    my $code;

    $code = $self->{ftp}->quot('STRU', 'R');
    unless ($code) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

    if ($code == 4 || $code == 5) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

  } elsif ($stru =~ /^page$/i) {
    my $code;

    $code = $self->{ftp}->quot('STRU', 'P');
    unless ($code) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

    if ($code == 4 || $code == 5) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

  } else {
    my $code;

    $code = $self->{ftp}->quot('STRU', $stru);
    unless ($code) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }

    if ($code == 4 || $code == 5) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->response_msg());
    }
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub allo {
  my $self = shift;
  my $size = shift;

  # XXX Net::FTP has a bug with its alloc() method, where a 202 response
  # code is incorrectly handled as an error.
  my $code = 0;

  $self->{ftp}->alloc($size);

  if ($self->{ftp}->code =~ /^(\d)/) {
    $code = $1;
  }

  if ($code == 4 || $code == 5) {
    croak("ALLO command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub noop {
  my $self = shift;
  my $code;

  $code = $self->{ftp}->quot('NOOP');
  unless ($code) {
    croak("NOOP command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  if ($code == 4 || $code == 5) {
    croak("NOOP command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub rnfr {
  my $self = shift;
  my $path = shift;
  my $code;

  $code = $self->{ftp}->quot('RNFR', $path);
  unless ($code) {
    croak("RNFR command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  if ($code == 4 || $code == 5) {
    croak("RNFR command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub rnto {
  my $self = shift;
  my $path = shift;
  my $code;

  $code = $self->{ftp}->quot('RNTO', $path);
  unless ($code) {
    croak("RNTO command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  if ($code == 4 || $code == 5) {
    croak("RNTO command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub quit {
  my $self = shift;

  unless ($self->{ftp}->quit()) {
    croak("QUIT command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub rest {
  my $self = shift;
  my $offset = shift;
  $offset = '' unless defined($offset);
  my $code;

  $code = $self->{ftp}->quot('REST', $offset);
  unless ($code) {
    croak("REST command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  if ($code == 4 || $code == 5) {
    croak("REST command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub nlst {
  my $self = shift;
  my $path = shift;
  $path = '' unless defined($path);

  my $res;

  $res = $self->{ftp}->nlst($path);
  unless ($res) {
    croak("NLST command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  if (ref($res)) {
    my $buf;
    while ($res->read($buf, 8192) > 0) {
    }

    $res->close();
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub nlst_raw {
  my $self = shift;
  my $path = shift;
  $path = '' unless defined($path);

  return $self->{ftp}->nlst($path);
}

sub list {
  my $self = shift;
  my $path = shift;
  $path = '' unless defined($path);

  my $res;

  $res = $self->{ftp}->list($path);
  unless ($res) {
    croak("LIST command failed: " .  $self->{ftp}->code . ' ' .
      $self->response_msg());
  }

  if (ref($res)) {
    my $buf;
    while ($res->read($buf, 8192) > 0) {
    }

    $res->close();
  }

  # XXX Work around bug in Net::FTP which fails to handle the case where,
  # for data transfers, a 150 response code may be sent (to open the data
  # connection), followed by an error response code.
  my $code = 0;

  if ($self->{ftp}->code =~ /^(\d)/) {
    $code = $1;
  }

  if ($code == 4 || $code == 5) {
    my $msg = $self->response_msg();
    $self->{mesg} = $msg;

    croak("LIST command failed: " .  $self->{ftp}->code . ' ' . $msg);
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub list_raw {
  my $self = shift;
  my $path = shift;
  $path = '' unless defined($path);

  return $self->{ftp}->list($path);
}

sub retr {
  my $self = shift;
  my $src_path = shift;
  $src_path = '' unless defined($src_path);
  my $dst_path = shift;
  $dst_path = '/dev/null' unless defined($dst_path);

  my $res;

  $res = $self->{ftp}->get($src_path, $dst_path);
  unless ($res) {
    croak("RETR command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (ref($res)) {
    my $buf;
    while ($res->read($buf, 8192) > 0) {
    }

    $res->close();
  }

  # XXX Work around bug in Net::FTP which fails to handle the case where,
  # for data transfers, a 150 response code may be sent (to open the data
  # connection), followed by an error response code.
  my $code = 0;

  if ($self->{ftp}->code =~ /^(\d)/) {
    $code = $1;
  }

  if ($code == 4 || $code == 5) {
    my $msg = $self->response_msg();
    $self->{mesg} = $msg;

    croak("RETR command failed: " .  $self->{ftp}->code . ' ' . $msg);
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub retr_raw {
  my $self = shift;
  my $path = shift;
  $path = '' unless defined($path);

  return $self->{ftp}->retr($path);
}

sub stor {
  my $self = shift;
  my $src_path = shift;
  $src_path = '' unless defined($src_path);
  my $dst_path = shift;
  $dst_path = '/dev/null' unless defined($dst_path);

  my $res;

  $res = $self->{ftp}->put($src_path, $dst_path);
  unless ($res) {
    croak("STOR command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  # XXX Work around bug in Net::FTP which fails to handle the case where,
  # for data transfers, a 150 response code may be sent (to open the data
  # connection), followed by an error response code.
  my $code = 0;

  if ($self->{ftp}->code =~ /^(\d)/) {
    $code = $1;
  }

  if ($code == 4 || $code == 5) {
    my $msg = $self->response_msg();
    $self->{mesg} = $msg;

    croak("STOR command failed: " .  $self->{ftp}->code . ' ' . $msg);
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub stor_raw {
  my $self = shift;
  my $path = shift;
  $path = '' unless defined($path);

  return $self->{ftp}->stor($path);
}

sub stou {
  my $self = shift;
  my $src_path = shift;
  $src_path = '' unless defined($src_path);
  my $dst_path = shift;

  my $res;

  $res = $self->{ftp}->put_unique($src_path, $dst_path);
  unless ($res) {
    croak("STOU command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  $self->{uniq} = $res;

  # XXX Work around bug in Net::FTP which fails to handle the case where,
  # for data transfers, a 150 response code may be sent (to open the data
  # connection), followed by an error response code.
  my $code = 0;

  if ($self->{ftp}->code =~ /^(\d)/) {
    $code = $1;
  }

  if ($code == 4 || $code == 5) {
    my $msg = $self->response_msg();
    $self->{mesg} = $msg;

    croak("STOU command failed: " .  $self->{ftp}->code . ' ' . $msg);
  }

  my $msg = $self->response_msg();
  if (wantarray()) {
    return ($self->{ftp}->code, $msg);

  } else {
    return $msg;
  }
}

sub stou_raw {
  my $self = shift;
  my $path = shift;
  $path = '' unless defined($path);

  return $self->{ftp}->stou($path);
}

1;
