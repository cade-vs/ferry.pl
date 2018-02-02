#!/usr/bin/perl
##############################################################################
##
##  Ferry.pl -- network file transporter
##  2010-2018 (c) Vladi Belperchinov-Shabanski "Cade"
##  <cade@biscom.net> <cade@datamax.bg>
##
##  DISTRIBUTED UNDER GPLv2 LICENSE, SEE "COPYING" FILE FOR DETAILS
##
##############################################################################
use POSIX;
use Fcntl qw( :flock );
use Socket;
use IO::Socket;
use IO::Socket::INET;
use FileHandle;
use Compress::Zlib;
use MIME::Base64;
use Storable qw( nfreeze thaw );
use Digest;
use Digest::SHA1;
use Digest::Whirlpool;
use strict;
use Data::Dumper;
use Data::HexDump;
use File::stat;

my $break_main_loop = 0;
my $opt_ssl = 0;
my $opt_ssl_key;
my $opt_ssl_crt;
my $opt_ssl_ca;
my $opt_ssl_verify;

##############################################################################

our $LISTEN_PORT      = 9900;
our $LOGDIR           = ".";
our $USE_LOGFILES     = 1;
our $CLONE_LOG_STDERR = 0;
our $FOREGROUND       = 0;

our $SLEEP = 5;

our $MODE;

our $DEBUG;

our $PEER_HOST;
our $PEER_PORT;

our $PEER_CERT;
our %PEER_SSL_CERT_SUBJECT;
our %PEER_SSL_CERT_ISSUER;

our $CONFIG;

##############################################################################

our $HELP = <<END;
usage: ferry.pl [mode] <options> [config-file]

mode:
    push  -- send files
    pull  -- receive files

options:
    -p port          -- listen on port different from $LISTEN_PORT (pull only)
    -l seconds       -- sleep time between loops (default: $SLEEP)
    -r               -- log only to STDERR (no log files)
    -rr              -- log to STDERR and logfiles
    -d               -- debug mode, multiple use is ok
                        (also DEBUG environment var)
    -s               -- require SSL to connect
    -sk key_file     -- key file for SSL (implies -s)
    -sc crt_file     -- certificate file for SSL (implies -s)
    -sa ca_file      -- require signed cert for SSL (implies -s)

END

our @args;
while( @ARGV )
  {
  $_ = shift;
  if( /^--+$/io )
    {
    push @args, @ARGV;
    last;
    }
  if( /-p(\d*)/ )
    {
    $LISTEN_PORT = $1 || shift;
    next;
    }
  if( /-l(\d*)/ )
    {
    $SLEEP = $1 || shift;
    $SLEEP = 5 if $SLEEP < 1;
    next;
    }
  if( /^-sk/ )
    {
    $opt_ssl_key = shift;
    $opt_ssl = 1;
    next;
    }
  if( /^-sc/ )
    {
    $opt_ssl_crt = shift;
    $opt_ssl = 1;
    next;
    }
  if( /^-sa/ )
    {
    $opt_ssl_ca = shift;
    $opt_ssl = 1;
    $opt_ssl_verify = 0x03; # verify + fail if no cert
    next;
    }
  if( /^-s/ )
    {
    $opt_ssl = 1;
    next;
    }
  if( /^-r(r)?/ )
    {
    $USE_LOGFILES     = 0;
    $USE_LOGFILES     = 1 if $1 eq 'r';
    $CLONE_LOG_STDERR = 1 if $1 eq 'r';
    next;
    }
  if( /^-d/ )
    {
    $DEBUG++;
    next;
    }
  if( /^-f/ )
    {
    $FOREGROUND = 1;
    next;
    }
  if( /^(--?h(elp)?|help)$/io )
    {
    print $HELP;
    exit;
    }
  push @args, $_;
  }

#use IO::Socket::SSL qw(debug3);
if( $opt_ssl )
  {
  eval { require IO::Socket::SSL; };
  die "SSL not available: $@" if $@;
  };

$MODE = lc shift( @args );

$MODE = 'push' if $MODE eq 'send';
$MODE = 'pull' if $MODE eq 'recv';

die "invalid mode, use --help\n" unless $MODE eq 'push' or $MODE eq 'pull';

##############################################################################

$SIG{ 'INT'  } = sub { $break_main_loop = 1; };
$SIG{ 'CHLD' } = \&child_sub;
$SIG{ 'USR1' } = \&usr1_sub;
$SIG{ 'PIPE' } = \&pipe_sub;

rcd_log( "status: start at " . scalar( localtime() ) );
rcd_log( "foreground mode, only 1 client will be accepted!" ) if $FOREGROUND;
rcd_log( "debug mode"   ) if $DEBUG;
rcd_log( "SSL required" ) if $opt_ssl;
rcd_log( "SSL key file:  $opt_ssl_key"     ) if $opt_ssl_key;
rcd_log( "SSL crt file:  $opt_ssl_crt"     ) if $opt_ssl_crt;
rcd_log( "SSL CA  file:  $opt_ssl_ca"      ) if $opt_ssl_ca;
rcd_log( "SSL verify:    $opt_ssl_verify"  ) if $opt_ssl_verify;

ferry_push() if $MODE eq 'push';
ferry_pull() if $MODE eq 'pull';

rcd_log( "status: exit at " . scalar( localtime() ) );

##############################################################################
### PULL #####################################################################
##############################################################################

sub ferry_pull
{
  my $SERVER;
  my $SERVER_SSL_TRAP_ERROR;

  $CONFIG = ferry_pull_config( shift @args );
  rcd_debug( "debug: pull config: \n" . Dumper( $CONFIG ) );

  if( $opt_ssl )
    {
    my %ssl_opts;

    $ssl_opts{ SSL_key_file    } = $opt_ssl_key    if $opt_ssl_key;
    $ssl_opts{ SSL_cert_file   } = $opt_ssl_crt    if $opt_ssl_crt;
    $ssl_opts{ SSL_ca_file     } = $opt_ssl_ca     if $opt_ssl_ca;
    $ssl_opts{ SSL_verify_mode } = $opt_ssl_verify if $opt_ssl_verify;
    $ssl_opts{ SSL_error_trap  } = sub { shift; $SERVER_SSL_TRAP_ERROR = shift; },

    $SERVER = IO::Socket::SSL->new(  Proto     => 'tcp',
                                     LocalPort => $LISTEN_PORT,
                                     Listen    => 5,
                                     ReuseAddr => 1,

                                     %ssl_opts,
                                   );
    }
  else
    {
    $SERVER = IO::Socket::INET->new( Proto     => 'tcp',
                                     LocalPort => $LISTEN_PORT,
                                     Listen    => 5,
                                     ReuseAddr => 1,

                                   );
    }

  if( ! $SERVER )
    {
    rcd_log( "fatal: cannot open server port $LISTEN_PORT: $!" );
    exit 100;
    }
  else
    {
    rcd_log( "status: listening on port $LISTEN_PORT" );
    }

  while(4)
    {
    last if $break_main_loop;
    my $CLIENT = $SERVER->accept();
    if( ! $CLIENT )
      {
      rcd_log( "fatal: $SERVER_SSL_TRAP_ERROR" ) if $opt_ssl and $SERVER_SSL_TRAP_ERROR;
      next;
      }

    my $peerhost = $CLIENT->peerhost();
    my $peerport = $CLIENT->peerport();
    my $sockhost = $CLIENT->sockhost();
    my $sockport = $CLIENT->sockport();


    rcd_log( "info: connection from $peerhost:$peerport to $sockhost:$sockport (me)" );
    # FIXME: check allowed/forbidden hosts...

    my $pid;
    if( ! $FOREGROUND )
      {
      $pid = fork();
      if( ! defined $pid )
        {
        die "fatal: fork failed: $!";
        }
      if( $pid )
        {
        rcd_log( "status: new process forked, pid = $pid" );
        next;
        }
      }
    # --------- child here ---------

    # reinstall signal handlers in the kid
    $SIG{ 'CHLD' } = 'DEFAULT';
    $SIG{ 'USR1' } = \&rcd_reopen_logs;

    $PEER_HOST = $CLIENT->peerhost();
    $PEER_PORT = $CLIENT->peerport();

    if( $opt_ssl )
      {
      my $subject  = $CLIENT->peer_certificate( "subject" );
      my $issuer   = $CLIENT->peer_certificate( "issuer"  );
      $PEER_CERT   = Net::SSLeay::PEM_get_string_X509( $CLIENT->peer_certificate() ) if $opt_ssl_ca;

      rcd_log( "debug: SSL cert subject: $subject" );
      rcd_log( "debug: SSL cert  issuer: $issuer"  );
      rcd_log( "debug: SSL cert    x509: $PEER_CERT" );
      cert_line_parse( \%PEER_SSL_CERT_SUBJECT, $subject );
      cert_line_parse( \%PEER_SSL_CERT_ISSUER,  $issuer  );
      }

    rcd_log( "debug: ----- new process here, peer: $PEER_HOST:$PEER_PORT -----" );
    $CLIENT->autoflush(1);

    pull_files( $CLIENT );

    $CLIENT->close();
    if( ! $FOREGROUND )
      {
      rcd_log( "debug: ----- process end here -----" );
      exit();
      }
    # ------- child ends here -------
    }
  close( $SERVER );
}

#-----------------------------------------------------------------------------

sub pull_files
{
  my $socket = shift;

  my $auth_rand = rand();

  send_msg( $socket, { AUTH_RAND => $auth_rand } );

  while(4)
    {
    last if $break_main_loop;

    my $hi = recv_msg( $socket );
    my $ho = {};

    return unless $hi;

    my $name = $hi->{ 'NAME' };
    if( ! exists $CONFIG->{ $name } )
      {
      rcd_log( "error: file send denied, unknown NAME" );
      send_msg( $socket, { STATUS => 'ENAME', STATUS_DES => 'unknown NAME' } );
      next;
      }

    my $au = $hi->{ 'AUTH' };
    my $pass = $CONFIG->{ $name }{ 'PASS' };
    my $auth = wp_hex( $auth_rand . $pass );
    if( $auth ne $au )
      {
      rcd_log( "error: authentication failed" );
      send_msg( $socket, { STATUS => 'EAUTH', STATUS_DES => 'authentication failed' } );
      rcd_log( "fatal: closing channel" );
      return;
      }

    my $fn = $hi->{ 'FILE_NAME' };
    my $fs = $hi->{ 'FILE_SIZE' };
    my $f1 = $hi->{ 'FILE_SHA1' };

    # FIXME: FIXME: FIXME: FIXME: FIXME: FIXME: FIXME: FIXME: FIXME: FIXME:
    my $fd = $CONFIG->{ $name }{ 'PATH' };
    if( ! -d $fd or ! -w $fd )
      {
      rcd_log( "error: file send denied, path not writable [$fd]" );
      send_msg( $socket, { STATUS => 'EACCESS', STATUS_DES => 'destination NAME not accessible' } );
      next;
      }

    if( $fn =~ /\// )
      {
      rcd_log( "error: file send denied, bad filename" );
      send_msg( $socket, { STATUS => 'EFILENAME', STATUS_DES => 'bad filename, no slashes allowed' } );
      next;
      }
    # FIXME: file exists? return EEXISTS
    # FIXME: file already received (sha1 check)? return ERECEIVED
    rcd_debug( "debug: about to send OK for file send" );
    send_msg( $socket, { STATUS => 'OK' } );

    my $in_fn = "$fd/$fn";
    rcd_debug( "debug: about to recv file data: $in_fn" );
    my $res = recv_file( $socket, $in_fn, $fs ); # FIXME: prefix?

    if( ! $res )
      {
      rcd_log( "error: cannot save incoming file [$in_fn]" );
      unlink( $in_fn );
      send_msg( $socket, { STATUS => 'ESAVE', STATUS_DES => "error: cannot save incoming file [$fn]" } );
      rcd_log( "fatal: closing channel" );
      return;
      }

    my $sha1 = sha1file( $in_fn );
    my $size = -s $in_fn;
    rcd_debug( "debug: expected file [$in_fn] size [$fs] sha1 [$f1]" );
    rcd_debug( "debug: incoming file [$in_fn] size [$size] sha1 [$sha1]" );

    if( $size != $fs )
      {
      my $msg = "error: wrong size for file [$fn] got [$size] expected [$fs], removing incoming file [$in_fn]";
      rcd_log( $msg );
      unlink( $in_fn );
      send_msg( $socket, { STATUS => 'ESIZE', STATUS_DES => $msg } );
      rcd_log( "fatal: closing channel" );
      return;
      }
    elsif( $sha1 eq '' or $f1 eq '' or $sha1 ne $f1 )
      {
      my $msg = "error: bad sha1 for file [$fn] got [$sha1] expected [$f1], removing incoming file [$in_fn]";
      rcd_log( $msg );
      unlink( $in_fn );
      send_msg( $socket, { STATUS => 'ESHA1', STATUS_DES => $msg } );
      rcd_log( "fatal: closing channel" );
      return;
      }
    else
      {
      rcd_log( "status: file recv OK [$fn:$fs:$f1]" );
      send_msg( $socket, { STATUS => 'OK', FILE_SHA1 => $sha1 } );
      }
    }
}

##############################################################################
### PUSH #####################################################################
##############################################################################

sub ferry_push
{
  my $SERVER;

  $CONFIG = ferry_push_config( shift @args );
  rcd_debug( "debug: push config: \n" . Dumper( $CONFIG ) );

  my %ssl_opts;

  $ssl_opts{ SSL_key_file    } = $opt_ssl_key    if $opt_ssl_key;
  $ssl_opts{ SSL_cert_file   } = $opt_ssl_crt    if $opt_ssl_crt;
  $ssl_opts{ SSL_ca_file     } = $opt_ssl_ca     if $opt_ssl_ca;
  $ssl_opts{ SSL_verify_mode } = $opt_ssl_verify if $opt_ssl_verify;
  $ssl_opts{ SSL_use_cert    } = 1 if $ssl_opts{ SSL_key_file  } or $ssl_opts{ SSL_cert_file  };

  # $ssl_opts{ SSL_error_trap  } = sub { shift; $SERVER_SSL_TRAP_ERROR = shift; },

  while(4)
    {
    last if $break_main_loop;

    SERV:

    for my $serv ( keys %$CONFIG )
      {
      # loop on all servers
      rcd_debug( "status: ----------------------------" );
      rcd_debug( "status: processing files for $serv" );

      for my $cfg_hr ( @{ $CONFIG->{ $serv } } )
        {
        # loop on all paths for a server
        my $path = $cfg_hr->{ 'PATH' };
        my $mask = $cfg_hr->{ 'MASK' };
        my $name = $cfg_hr->{ 'NAME' };

        rcd_debug( "status: processing path [$path] for [$serv:$name]" );

        if( ! -d $path or ! -r $path )
          {
          rcd_log( "error: path not readable [$path] skipping to next path" );
          next;
          }
        if( ! -d "$path/sent" or ! -w "$path/sent" )
          {
          rcd_log( "error: path not writable [$path/sent] skipping to next path" );
          next;
          }

        my @files = glob "$path/$mask";

        @files = grep { ! -d } @files;          # skip directories
        @files = grep { ! /$\.part$/i } @files; # skip partial files

        if( @files == 0 )
          {
          rcd_log( "status: no files found to send, skipping to next path" );
          next;
          }
        else
          {
          my $fc = @files;
          rcd_log( "status: found files to send: $fc" );
          }

        # sort by time, if equal, sort by name
        @files = sort { stat($a)->mtime <=> stat($b)->mtime || $a cmp $b } @files;

        my $SERVER;

        if( $opt_ssl )
          {
          $SERVER = IO::Socket::SSL->new(  Proto    => 'tcp',
                                           PeerAddr => $serv,

                                           %ssl_opts,
                                        );
          }
        else
          {
          $SERVER = IO::Socket::INET->new( Proto    => 'tcp',
                                           PeerAddr => $serv,
                                         );
          }

        if( ! $SERVER )
          {
          rcd_log( "error: cannot connect to [$serv] reason: $!" );
          rcd_log( "status: skipping to next server" );
          next SERV;
          }

        $SERVER->autoflush(1);

        push_files( $SERVER, \@files, $cfg_hr );

        $SERVER->close();

        # loop on all paths for a server
        }
      # loop on all servers
      }

    sleep( $SLEEP );
    }
}

#-----------------------------------------------------------------------------

sub push_files
{
  my $socket = shift;
  my $files  = shift;
  my $cfg_hr = shift;

  my $auth_hr   = recv_msg( $socket );
  my $auth_rand = $auth_hr->{ 'AUTH_RAND' };

  my $name = $cfg_hr->{ 'NAME' };
  my $pass = $cfg_hr->{ 'PASS' };
  my $auth = wp_hex( $auth_rand . $pass );

  while( @$files )
    {
    my $hi = {};
    my $ho = {};

    my $file = shift @$files;

    my $fp = './';
    my $fn = $file;
    if( $file =~ /^(.+?)\/([^\/]+)$/ )
      {
      $fp = $1;
      $fn = $2;
      }

    my $sha1 = sha1file( $file );
    my $size = -s $file;

    rcd_debug( "debug: sending message/fileinfo [$fn]" );
    send_msg( $socket,
              {
              NAME      => $name,
              AUTH      => $auth,
              FILE_NAME => $fn,
              FILE_SIZE => $size,
              FILE_SHA1 => $sha1,
              }
            );
    rcd_debug( "debug: awaiting OK for file send [$fn]" );
    $ho = recv_msg( $socket );
    if( ! $ho )
      {
      rcd_log( "fatal: closing channel" );
      return;
      }

    my $st = $ho->{ 'STATUS' };
    if( $st ne 'OK' )
      {
      my $sd = $ho->{ 'STATUS_DES' };
      rcd_log( "error: file send denied [$file] reason: $st: $sd" );
      # FIXME: postpone this file?
      next;
      }

    rcd_debug( "debug: sending file [$file]" );
    my $res = send_file( $socket, $file );

    if( ! $res )
      {
      rcd_log( "error: error sending file [$file]" );
      rcd_log( "fatal: closing channel" );
      next;
      }
    else
      {
      $ho = recv_msg( $socket );
      my $st = $ho->{ 'STATUS' };
      if( $st eq 'OK' and $sha1 eq $ho->{ 'FILE_SHA1' } )
        {
        rcd_debug( "status: file sent OK [$fp/$fn] size [$size] sha1 [$sha1]" );
        my $res = rename( "$fp/$fn", "$fp/sent/$fn" );
        die "fatal: cannot move file [$fp/$fn] to [$fp/sent/$fn]" unless $res;
        }
      else
        {
        my $sd = $ho->{ 'STATUS_DES' };
        rcd_log( "error: error sending file [$file] reason: $st: $sd" );
        }
      }

    }
}

##############################################################################
### CONFIG ###################################################################
##############################################################################

sub ferry_push_config
{
  my $fn = shift;

  my %conf;

  my $if;
  open( $if, $fn ) or die "cannot open PUSH config file [$fn]\n";

  while( <$if> )
    {
    chomp;
    next if /^\s*[#;]/;
    next unless /\S/;
    s/^\s*//;

    if( /^(\S+?)\/([^\/]+)\s+(\S+):((\d+):)?([A-Z_0-9]+)\s*(\S*)/i )
      {
      my $path = $1;
      my $mask = $2;

      my $serv = $3;
      my $port = $5 || $LISTEN_PORT;
      my $name = uc $6;

      my $pass = $7;

      my $key = "$serv:$port";

      $conf{ $key } ||= [];
      push @{ $conf{ $key } }, {
                               PATH => $path,
                               MASK => $mask,
                               SERV => $serv,
                               PORT => $port,
                               NAME => $name,
                               PASS => $pass,
                               };

      }
    else
      {
      die "malformed PUSH config line [$fn:$.] [$_]\n";
      }

    }

  close( $if );

  return \%conf;
}

sub ferry_pull_config
{
  my $fn = shift;

  my %conf;

  my $if;
  open( $if, $fn ) or die "cannot open PULL config file [$fn]\n";

  while( <$if> )
    {
    chomp;
    next if /^\s*[#;]/;
    s/^\s*//;
    next unless /\S/;

    if( /^([A-Z_0-9]+)\s+(\S+)\s*(\S+)/i )
      {
      my $name = uc $1;
      my $path = $2;
      my $pass = $3;

      $conf{ $name } = {
                       PATH => $path,
                       NAME => $name,
                       PASS => $pass,
                       };

      }
    else
      {
      die "malformed PULL config line [$fn:$.] [$_]\n";
      }

    }

  close( $if );

  return \%conf;
}

##############################################################################
### UTIL #####################################################################
##############################################################################

sub recv_msg
{
  my $socket = shift;

  my $dlen;
  my $rc_dlen = $socket->read( $dlen, 10 );
  if( $rc_dlen == 0 )
    {
    rcd_debug( "debug: end of communication channel: $!" );
    return undef;
    }
  if( $rc_dlen != 10 or $dlen < 0 or $dlen > 99_999_999 )
    {
    rcd_log( "fatal: invalid length received, got dle [$rc_dlen], expected 10" );
    return undef;
    }

  my $data;
  my $rc_data = $socket->read( $data, $dlen );
  if( $rc_data < 1 or $rc_data != $dlen )
    {
    rcd_log( "fatal: read data failed, expected dle [$dlen], got [$rc_data]" );
    return undef;
    }

  rcd_debug( "debug: MSGMSGMSGMSGMSGMSGMSG:\n" . HexDump($data) ) if $DEBUG > 2;

  my $hr = bin2hash( $data );

  rcd_debug( "debug: <<<<<<<<<<<<<<<<<<<<<<<<<:\n" . Dumper( $hr ) ) if $DEBUG > 1;

  if( ! $hr )
    {
    rcd_log( "error: cannot decode message, ignored" );
    return undef;
    }

  return $hr;
}

sub send_msg
{
  my $socket = shift;
  my $hr     = shift;

  rcd_debug( "debug: >>>>>>>>>>>>>>>>>>>>>>>>>:\n" . Dumper( $hr ) ) if $DEBUG > 1;

  my $data = hash2bin( $hr );

  rcd_debug( "debug: MSGMSGMSGMSGMSGMSGMSG:\n" . HexDump($data) ) if $DEBUG > 2;

  my $dlen = sprintf( '%010d', length( $data ) );
  $socket->print( $dlen . $data );

  return 1;
}

sub recv_file
{
  my $socket    = shift;
  my $file_name = shift;
  my $file_size = shift;
  my $prefix    = shift;

  $file_name = $prefix . $file_name if $prefix ne '';

  my $FO;
  my $res;

  $res = open( $FO, '>', $file_name . '.part' );
  if( ! $res )
    {
    rcd_log( "error: cannot create new file [$file_name] reason: $!" );
    return 0;
    }
  my $buf_size = 1024*1024;
  my $read;
  my $data;
  while(4)
    {
    my $read_size = $file_size > $buf_size ? $buf_size : $file_size;
    $read = $socket->read( $data, $read_size );
    print $FO $data;
    last unless $read > 0;
    $file_size -= $read;
    last if $file_size == 0;
    }
  close( $FO );
  if( $file_size != 0 )
    {
    rcd_log( "error: received file has wrong size, difference [$file_size]" );
    unlink( $file_name . '.part' );
    return 0;
    }
  $res = rename( $file_name . '.part', $file_name );
  if( ! $res )
    {
    rcd_log( "error: cannot rename file [$file_name] reason: $!" );
    unlink( $file_name . '.part' );
    return 0;
    }

  return 1;
}

sub send_file
{
  my $socket    = shift;
  my $file_name = shift;

  my $FI;
  my $res = open( $FI, $file_name );
  if( ! $res )
    {
    rcd_log( "error: cannot open file: $file_name" );
    return 0;
    }

  my $size = -s $file_name;

  my $data;
  my $buf_size = 1024*1024;
  my $read;
  while(4)
    {
#print "++++++++++++++++++++++++++++++++++++++++++++\n";
    $read = read( $FI, $data, $buf_size );
#print "=========================================$read==$buf_size===\n";
    $socket->print( $data ) if $read > 0;
#print "********************************************\n";
    last if $read < $buf_size;
    # FIXME: check $size?
    }
  close( $FI );

  return 1;
}

#-----------------------------------------------------------------------------

sub hash2bin
{
  my $ref = shift;

  ref( $ref ) eq 'HASH' or die "hash2bin(): hash reference required!\n"; # FIXME: boom! move boom into COMMON!

  my $fz = Compress::Zlib::memGzip( nfreeze( $ref ) );

  return $fz;
};

sub bin2hash
{
  my $fz = shift;

  my ( $ref ) = thaw( Compress::Zlib::memGunzip( $fz ) );

  return ref( $ref ) eq 'HASH' ? $ref : undef;
};

sub sha1file
{
  my $fn = shift;

  return undef if -d $fn;

  my $if;
  open( $if, $fn ) or return undef;
  my $sha1 = new Digest::SHA1;
  $sha1->addfile( $if );
  close( $if );

  return $sha1->hexdigest();
}

#-----------------------------------------------------------------------------

sub child_sub
{
  my $kid;
  while( ( $kid = waitpid( -1, WNOHANG ) ) > 0 )
    {
    rcd_log( "status: sigchld received [$kid]" );
    }
  $SIG{ 'CHLD' } = \&child_sub;
}

sub usr1_sub
{
  rcd_log( "status: sigusr1 received" );
  $SIG{ 'USR1' } = \&usr1_sub;
}

sub usr1_sub
{
  rcd_log( "status: sigpipe received" );
  $SIG{ 'PIPE' } = \&pipe_sub;
}

##############################################################################

our %LOGS;
our $last_log_message;
our $last_log_message_count;

sub rcd_log
{
  for my $s ( @_ )
    {
    if ($last_log_message eq $s)
      {
      $last_log_message_count++;
      next;
      }

    my $type = 'unknown';
    $type = lc $1 if $s =~ /^([a-z]+):/;
    next if $type eq 'debug' and ! $DEBUG;
    my @types = ( $type );
    push @types, 'global' if $USE_LOGFILES;

    # write in order to prevent deadlock caused by flock
    for my $type ( sort @types )
      {
      my $fh = $LOGS{ $type };
      if( $USE_LOGFILES and ! $fh )
        {
        open( $fh, ">>$LOGDIR/$MODE-$type.log" );
        $LOGS{ $type } = $fh;
        }
      else
        {
        $fh = $LOGS{ $type };
        }
      $fh = \*STDERR unless $fh;

      my $tm = strftime( "%Y%m%d-%H%M%S", localtime() );

      flock( $fh, LOCK_EX );
      print $fh "$tm $MODE" . "[$$]" . ": last message repeated $last_log_message_count times...\n"
          if $last_log_message_count;
      $last_log_message = $s;
      $last_log_message_count = 0;
      my $log_msg = "$tm $MODE" . "[$$]" . ": $s\n";
      print $fh $log_msg;
      flock( $fh, LOCK_UN );
      if( $CLONE_LOG_STDERR and $fh ne \*STDERR and $type eq 'global' )
        {
        print STDERR $log_msg;
        }
      }
    }
}

sub rcd_debug
{
  return if $DEBUG < 1;
  rcd_log( @_ );
}

sub rcd_debug2
{
  return if $DEBUG < 2;
  rcd_log( @_ );
}

sub rcd_debug_dumper
{
  return unless $DEBUG;
  my ( $pack, $file, $line, $subname ) = caller( 0 );
  rcd_log( "debug: DUMPER DATA FOLLOWS @ $file:$line --------------\n" . Dumper( @_ ) );
}

sub cert_line_parse
{
  my $hr = shift; # destination hash
  my $line = shift; # cert line like: /C=BG/ST=Sofia/L=Sofia/O=DataMax...

  my $c;
  for( split /\//, $line )
    {
    next unless /^([^=]+)=(.*)$/;
    $hr->{ uc $1 } = $2;
    $c++;
    }
  return $c;
}

sub wp_hex
{
  my $s = shift;

  my $wp = Digest->new( 'Whirlpool' );
  $wp->add( $s );
  my $hex = $wp->hexdigest();

  return $hex;
}


##############################################################################

###EOF########################################################################

