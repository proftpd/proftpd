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
    return $msg;
  }

  return $self->{ftp}->message;
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

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub pwd {
  my $self = shift;

  unless ($self->{ftp}->pwd()) {
    croak("PWD command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub xpwd {
  my $self = shift;
  my $code;

  $code = $self->{ftp}->quot('XPWD');
  unless ($code) {
    croak("XPWD command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if ($code == 4 || $code == 5) {
    croak("XPWD command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub cwd {
  my $self = shift;
  my $dir = shift;

  unless ($self->{ftp}->cwd($dir)) {
    croak("CWD command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub xcwd {
  my $self = shift;
  my $dir = shift;
  my $code;

  $code = $self->{ftp}->quot('XCWD', $dir);
  unless ($code) {
    croak("XCWD command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if ($code == 4 || $code == 5) {
    croak("XCWD command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub cdup {
  my $self = shift;
  my $dir = shift;

  unless ($self->{ftp}->cdup()) {
    croak("CDUP command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub xcup {
  my $self = shift;
  my $code;

  $code = $self->{ftp}->quot('XCUP');
  unless ($code) {
    croak("XCUP command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if ($code == 4 || $code == 5) {
    croak("XCUP command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub syst {
  my $self = shift;
  my $code;

  $code = $self->{ftp}->quot('SYST');
  unless ($code) {
    croak("SYST command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if ($code == 4 || $code == 5) {
    croak("SYST command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub mkd {
  my $self = shift;
  my $dir = shift;

  unless ($self->{ftp}->mkdir($dir)) {
    croak("MKD command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub xmkd {
  my $self = shift;
  my $dir = shift;
  my $code;

  $code = $self->{ftp}->quot('XMKD', $dir);
  unless ($code) {
    croak("XMKD command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if ($code == 4 || $code == 5) {
    croak("XMKD command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub rmd {
  my $self = shift;
  my $dir = shift;

  unless ($self->{ftp}->rmdir($dir)) {
    croak("RMD command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub xrmd {
  my $self = shift;
  my $dir = shift;
  my $code;

  $code = $self->{ftp}->quot('XRMD', $dir);
  unless ($code) {
    croak("XRMD command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if ($code == 4 || $code == 5) {
    croak("XRMD command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub dele {
  my $self = shift;
  my $path = shift;

  unless ($self->{ftp}->delete($path)) {
    croak("DELE command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub type {
  my $self = shift;
  my $type = shift;

  if ($type =~ /^ascii$/i) {
    unless ($self->{ftp}->ascii()) {
      croak("TYPE command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

  } elsif ($type =~ /^binary$/i) {
    unless ($self->{ftp}->binary()) {
      croak("TYPE command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

  } else {
    my $code;

    $code = $self->{ftp}->quot('TYPE', $type);
    unless ($code) {
      croak("TYPE command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

    if ($code == 4 || $code == 5) {
      croak("TYPE command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub mdtm {
  my $self = shift;
  my $path = shift;

  unless ($self->{ftp}->mdtm($path)) {
    croak("MDTM command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub size {
  my $self = shift;
  my $path = shift;

  unless ($self->{ftp}->size($path)) {
    croak("SIZE command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub pasv {
  my $self = shift;

  unless ($self->{ftp}->pasv()) {
    croak("PASV command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub port {
  my $self = shift;
  my $port = shift;

  unless ($self->{ftp}->port($port)) {
    croak("PORT command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
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
        $self->{ftp}->message);
    }

    if ($code == 4 || $code == 5) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

  } elsif ($mode =~ /^block$/i) {
    my $code;

    $code = $self->{ftp}->quot('MODE', 'B');
    unless ($code) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

    if ($code == 4 || $code == 5) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

  } elsif ($mode =~ /^compress(ed)?$/i) {
    my $code;

    $code = $self->{ftp}->quot('MODE', 'C');
    unless ($code) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

    if ($code == 4 || $code == 5) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

  } else {
    my $code;

    $code = $self->{ftp}->quot('MODE', $mode);
    unless ($code) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

    if ($code == 4 || $code == 5) {
      croak("MODE command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
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
        $self->{ftp}->message);
    }

    if ($code == 4 || $code == 5) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

  } elsif ($stru =~ /^record$/i) {
    my $code;

    $code = $self->{ftp}->quot('STRU', 'R');
    unless ($code) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

    if ($code == 4 || $code == 5) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

  } elsif ($stru =~ /^page$/i) {
    my $code;

    $code = $self->{ftp}->quot('STRU', 'P');
    unless ($code) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

    if ($code == 4 || $code == 5) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

  } else {
    my $code;

    $code = $self->{ftp}->quot('STRU', $stru);
    unless ($code) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }

    if ($code == 4 || $code == 5) {
      croak("STRU command failed: " .  $self->{ftp}->code . ' ' .
        $self->{ftp}->message);
    }
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
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
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub noop {
  my $self = shift;
  my $code;

  $code = $self->{ftp}->quot('NOOP');
  unless ($code) {
    croak("NOOP command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if ($code == 4 || $code == 5) {
    croak("NOOP command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub rnfr {
  my $self = shift;
  my $path = shift;
  my $code;

  $code = $self->{ftp}->quot('RNFR', $path);
  unless ($code) {
    croak("RNFR command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if ($code == 4 || $code == 5) {
    croak("RNFR command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub rnto {
  my $self = shift;
  my $path = shift;
  my $code;

  $code = $self->{ftp}->quot('RNTO', $path);
  unless ($code) {
    croak("RNTO command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if ($code == 4 || $code == 5) {
    croak("RNTO command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub quit {
  my $self = shift;

  unless ($self->{ftp}->quit()) {
    croak("QUIT command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub rest {
  my $self = shift;
  my $offset = shift;
  my $code;

  $code = $self->{ftp}->quot('REST', $offset);
  unless ($code) {
    croak("REST command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if ($code == 4 || $code == 5) {
    croak("REST command failed: " .  $self->{ftp}->code . ' ' .
      $self->{ftp}->message);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
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
      $self->{ftp}->message);
  }

  if (ref($res)) {
    my $buf;
    while ($res->read($buf, 8192) > 0) {
    }

    $res->close();
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
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
    # In this case, due to Net::FTP's bugs, the response message will
    # contain messages from both the successful 1x response and the failure
    # 4x/5x response.
    #
    # To get just the failure message, we call message() in a list context,
    # and return the second element.
    my @msgs = $self->{ftp}->message;

    my $msg = $msgs[1];
    chomp($msg);
    $self->{mesg} = $msg;

    croak("LIST command failed: " .  $self->{ftp}->code . ' ' . $msg);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
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
  my $path = shift;
  $path = '' unless defined($path);

  my $res;

  $res = $self->{ftp}->get($path);
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
    # In this case, due to Net::FTP's bugs, the response message will
    # contain messages from both the successful 1x response and the failure
    # 4x/5x response.
    #
    # To get just the failure message, we call message() in a list context,
    # and return the second element.
    my @msgs = $self->{ftp}->message;

    my $msg = $msgs[1];
    chomp($msg);
    $self->{mesg} = $msg;

    croak("RETR command failed: " .  $self->{ftp}->code . ' ' . $msg);
  }

  if (wantarray()) {
    return ($self->{ftp}->code, $self->{ftp}->message);

  } else {
    return $self->{ftp}->message;
  }
}

sub retr_raw {
  my $self = shift;
  my $path = shift;
  $path = '' unless defined($path);

  return $self->{ftp}->retr($path);
}

1;
