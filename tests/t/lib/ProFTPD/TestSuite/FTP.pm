package ProFTPD::TestSuite::FTP;

use strict;

use Carp;
use Net::FTP;
use POSIX qw(:sys_wait_h);

sub new {
  my $class = shift;
  my ($addr, $port, $timeout) = @_;
  $timeout = 10 unless defined($timeout);
 
  my $ftp;

  my $now = time();

  # Creating a Net::FTP object involves attempting to connect to the given
  # address/port.  So handle the test cases where the server process may
  # not yet be completely up, retry this connect, once a second, up to the
  # given timeout.

  while (1) {
    if (time() - $now > $timeout) {
      croak("Unable to connect to $addr:$port: Timed out after $timeout secs");
    }

    $ftp = Net::FTP->new(
      Host => $addr,
      Port => $port,
    );

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
  my $res;

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

1;
