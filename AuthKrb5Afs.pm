#! /usr/bin/perl -w
# Apache::AuthKrb5Afs - integrated Krb5+OpenAFS login for Apache
# Noel Burton-Krahn <noel@bkbox.com>
# Dec 14, 2003
#
# see the pod at the __END__ for docs
#
# Copyright (C) 2003 Noel Burton-Krahn <noel@bkbox.com>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


package Apache::AuthKrb5Afs;
use strict;
use Apache;
use Apache::Constants qw(:common);
use File::stat;
use File::Path;
use File::Basename;
use Fcntl;
use Auth::Krb5Afs;
use MIME::Base64;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Data::Dumper;

require Exporter;
our @ISA = qw(Exporter);
our $VERSION = '1.0';

my($COOKIE_ROOT) = "/tmp/AuthKrb5Afs";
my($COOKIE_NAME) = "AuthKrb5Afs";
my($COOKIE_MAX_TIME) = 60*60*24; 
my($COOKIE_RENEW_TIME) = 60*20;
my($COOKIE_CLEAN_TIME) = 60;
my($SECURE_COOKIE) = 0;

sub debug {
    #my(@l) = caller(1);
    #warn(basename($l[1]), ":", $l[2], "[$$] ", @_, "\n");
}

sub new {
    bless({}, shift);
}

# get or set errors in a hash table
sub err {
    my($self) = shift;
    
    return $self->{err} unless(@_);

    my($k, $v);
    $k = shift;
    $v = join('', @_);
    debug("error: $k: $v");
    $self->{err} ||= {};
    $self->{err}{$k} .= '\n' if( $self->{err}{$k} );
    $self->{err}{$k} .= $v;
}

# make sure the COOKIE_ROOT exists, expire old cookies, and try to get
# a new one
sub new_cookie {
    my($self) = shift;
    my($path) = @_;
    my($i, $cookie);

    # debug
    debug("new_cookie: path=$path");

    # make sure the cookie directory exists
    if( ! -d $COOKIE_ROOT ) {
	mkpath([$COOKIE_ROOT], 0, 0777);
	if( ! -d $COOKIE_ROOT ) {
	    return undef;
	}
    }

    # expire old cookies
    my($st, $t, $f);
    $f = "$COOKIE_ROOT/last_cleaned";
    my($st) = stat($f);
    $t = time();
    if( !$st || $t - $st->mtime() > $COOKIE_CLEAN_TIME ) {
	unlink($f);
	open(F, ">$f");
	close(F);
	utime($t, $t, $f);
	
	opendir(D, $COOKIE_ROOT);
	while($f = readdir(D) ) {
	    $f = "$COOKIE_ROOT/$f";

	    next unless -f $f;
	    $st = stat($f);
	    
	    # debug
	    debug("stat($f)=$st");

	    unlink($f) if( $t - $st->mtime() > $COOKIE_MAX_TIME );
	}
	closedir(D);
    }

    # try to ge a new cookie
    for($i=0; $i<1000; $i++) {
	$cookie = sprintf("%s_%04x%04x%04x%04x", 
			  $COOKIE_NAME,
			  rand(0xffff), rand(0xffff), rand(0xffff), rand(0xffff));
	sysopen(F, "$path/$cookie", O_RDWR|O_CREAT|O_EXCL, 0600) && last;
	$cookie = undef;
    }
    close(F);
    return $cookie;
}

# gets a kerberos ticket next to the $cookie_path and returns it
sub cookie_auth_krb {
    my($self) = shift;
    my($user, $pass, $cookie_path) = @_;
    my($req) = Apache->request();
    my($krb5cc_path);
    my($i, $s);
    my($pid);
    my($pwent);

    my($err) = -1;
    TRY: {
	$krb5cc_path = "$cookie_path.krb5cc";
	unlink($krb5cc_path);

	$ENV{KRB5CCNAME} = $krb5cc_path;
	$req->subprocess_env('KRB5CCNAME', $ENV{KRB5CCNAME});

	# debug
	debug("cookie_auth_krb: ENV{KRB5CCNAME}=$ENV{KRB5CCNAME}");

	($err, $pwent) = Auth::Krb5Afs->authenticate($user, $pass);
	if( $err ) {
	    my($k, $v);
	    while( ($k, $v) = each(%$err) ) {
		$self->err($k, $v);
	    }
	    last;
	}

	$ENV{REMOTE_USER} = $ENV{USER};
	chown $pwent->{uid}, $krb5cc_path;

	$err=0;
    }
    if( $err ) {
	if( $krb5cc_path ) {
	    unlink($krb5cc_path);
	    $krb5cc_path = undef;
	}
    }

    return $krb5cc_path;
}

sub get_cookie {
    my($self) = shift;
    my($req) = @_;
    my($cookie);

    TRY: {
	$cookie = $req->header_in('Cookie');

	# debug
	debug("get_cookie: Cookie=$cookie");

	last unless $cookie;
	
	last unless $cookie =~ /$COOKIE_NAME=(\w+)/;
	return $1;
    }
    return undef;
}

# try to renew an existing cookie
sub cookie_check {
    my($self) = shift;
    my($req, $cookie) = @_;

    my($cookie_path);
    my($s, $t);
    my($err) = -1;

    TRY: {
	last unless($cookie);
	$cookie_path="$COOKIE_ROOT/$cookie";

	my($st) = stat("$cookie_path.krb5cc");
	
	# debug
	debug("cookie_check: stat($cookie_path.krb5cc)=$st");

	last unless($st);
	
	$ENV{KRB5CCNAME}="$cookie_path.krb5cc";
	$req->subprocess_env('KRB5CCNAME', $ENV{KRB5CCNAME});

	# renew the krb ticket every few mintues
	$t = time();
	if( $t - $st->mtime() > $COOKIE_RENEW_TIME/2 ) {
	    $s = `kinit -R 2>&1`;
	    if( $? ) {
		$self->err("", "renewing kerberos ticket: KRB5CCNAME=$ENV{KRB5CCNAME} ?=$? s=$s $!");
		last;
	    }
	    utime($t, $t, $ENV{KRB5CCNAME});
	}

	$s = `aklog -setpag 2>&1`;
	if( $? ) {
	    $self->err("", "aklog: $!");
	    last;
	}

	# get the user name from the tokens
	$s = `tokens 2>&1`;

	# debug
	debug("cookie_ckeck: tokens=$s");

	my($name,$passwd,$uid,$gid,
	   $quota,$comment,$gcos,$dir,$shell,$expire);
	
	while($s =~ /\(AFS ID (\d+)\)/mg) {
	    ($name,$passwd,$uid,$gid,
	     $quota,$comment,$gcos,$dir,$shell,$expire) = getpwuid($1);
	    next unless $name;
	    
	    # debug
	    debug("handler: user=$name dir=$dir");
	    
	    $req->subprocess_env('USER', $name);
	    $req->subprocess_env('REMOTE_USER', $name);
	    $req->subprocess_env('HOME', $dir);
	    $req->connection->user($name);
	    last;
	}
	
	if( !$name ) {
	    $self->err("", "can't find user for AFS id=$1");
	    #last;
	}
	
	$req->subprocess_env('AUTH_COOKIE', $cookie);
	$req->subprocess_env('AUTH_COOKIE_PATH', $cookie_path);

	$err = 0;
    }
    return $err;
}

sub authen_handler {
    my($req) = shift;
    my($user) = $req->subprocess_env('USER');
    $req->connection->user($user) if( $user );
    return 0;
}

sub trans_handler {
    my($req, $cookie) = @_;

    my($self) = Apache::AuthKrb5Afs->new();
    my($cookie_path, $krb5cc_path);
    my($user, $pass);
    my($i, $s, @l);
    my($basic_auth) = 0;
    my($err) = -1;
    
    TRY: {
        # try an existing cookie
        $cookie = $self->get_cookie($req);
	
	# debug
	debug("AuthKrb5Afs: handler pid=$$"
	     . " " . $req->method() . " " . $req->uri()
	     . " cookie=$cookie" 
	     . " headers_in=" . Dumper( \%{$req->headers_in()} )
	     );

	# treat a basic "Authorization" header like a cookie
        if( !$cookie
            && ($s = $req->header_in("Authorization"))
            && ($s =~ /^Basic (.*)/)
            && ($s = decode_base64($1))
            && (($user, $pass) = split(/:/, $s, $2))
            && $user
            && $pass
            ) {
	    
	    $basic_auth=1;
	    $cookie = md5_hex($req->header_in("Authorization"));
	    $err = $self->cookie_check($req, $cookie);
	    if( !$err ) {
		last;
	    }
	    
 	    # couldn't renew cookie, get a new one
	    $krb5cc_path = $self->cookie_auth_krb($user, $pass, 
						  "$COOKIE_ROOT/$cookie");
	    last unless( $krb5cc_path );
	    $err = 0;
	}
	elsif( $cookie ) {
	    $err = $self->cookie_check($req, $cookie);
	}
    }

    # debug
    debug("AuthKrb5Afs: handler basic_auth=$basic_auth cookie=$cookie cookie_check=$err uri=" . $req->uri() );
    
    # forget the cookie if there was an error
    if( $err ) {
	if( $cookie ) {
	    if( $basic_auth ) {
		$req->note_basic_auth_failure();
	    }
	    $req->err_header_out('Set-Cookie' => 
				 "$COOKIE_NAME=; Max-Age=0; Path=/");
	    $self->destroy_cookie($cookie);
	}
	#`unlog`;
    }
 
    # if they're authenticated, let them have access to the whole
    # AFS space!
    if( !$err && $s =~ m!^/afs/! ) {
	$req->filename($s);
	$req->document_root("/");
    }

    # debug
    if( $self->err() ) {
    	debug("handler: err=" . Dumper($self->err()));
    }
    
    return &DECLINED;
}

sub login_handler {
    my($req) = @_;
    my($self) = Apache::AuthKrb5Afs->new();
    my($s, %args);
     
    my($user, $redirect);

    # debug
    debug("login_handler");

    my($prev) = $req->prev();
    if($prev) {
	# DAV and other non-HTML requests require a "401
	# Authentication Requied" rather than an HTML form to enter the password
	my($login_401);
	$login_401 = (($prev->method ne 'GET')
		      || ($prev->header_in('User-Agent') =~ /\bdav\b/i)
		      || !($prev->header_in('Accept') =~ /(\*\/\*|text\/html)/i)
		      );
	if( $login_401 ) {
	    # debug
	    debug("login-catch: status=401");
	    
	    $req->status(401);
	    $req->err_header_out("WWW-Authenticate", "Basic realm");
	    $req->send_http_header();
	    return OK;
	}

	$redirect = $prev->uri();
	if( $prev->method eq 'POST' ) {
	    $prev->read($s, $prev->header_in('content-length'));
	    $prev->args($s);
	}
	if( $s = $prev->args() ) {
	    $redirect .= "?$s";
	}
    }

    if( $req->method eq 'POST' ) {
	$req->read($s, $req->header_in('content-length'));
	$req->args($s);
    }
    %args = $req->args();

    $user = $args{user};
    $redirect = $args{redirect} if( $args{redirect} );
    
    $redirect ||= $ENV{AUTHKRB5AFS_LOGIN_FORM} || '/login.pl';

    my($err);
    if( %args ) {
	$err = $self->login();
	# redirect to prev
	if( !$err ) {
	    $req->status(302);
	    $req->err_header_out("Location", $redirect);
	    $req->send_http_header();
	    return OK;
	}
    }

    # use another script to display the login form
    $s = $ENV{AUTHKRB5AFS_LOGIN_FORM} || '/login.pl';

    # debug
    debug("login_handler internal_redirect($s) err=" . Dumper($err));

    $req->subprocess_env("AUTHKRB5AFS_ERR_USER", delete($err->{user}));
    $req->subprocess_env("AUTHKRB5AFS_ERR_PASS", delete($err->{pass}));
    $req->subprocess_env("AUTHKRB5AFS_ERR_OTHERS", join("\n", keys(%$err)));
    $req->subprocess_env("AUTHKRB5AFS_REDIRECT", $redirect);
    $req->subprocess_env("AUTHKRB5AFS_USER", $user);
    $req->subprocess_env("AUTHKRB5AFS_LOGIN_HANDLER", 
			 $ENV{AUTHKRB5AFS_LOGIN_HANDLER} || '/login');
    $req->internal_redirect($s);

    return OK;
}

sub login {
    my($self) = shift;
    my($req);
    eval {
	$req = Apache->request();
    };
    my($cookie, $cookie_path, $krb5cc_path);
    my($s);
    my(%args);

    my($err) = -1;
    TRY: {
	%args = $req->args();

	# debug
 	debug("login: user=" . $args{user} . " pass=" . $args{pass});
	$cookie = $self->new_cookie($COOKIE_ROOT);

	# debug
	debug("login: cookie=$cookie path=$COOKIE_ROOT/$cookie");

	if( !$cookie ) {
	    $self->err("", "Can't make new cookie in $COOKIE_ROOT");
	    last;
	}

	$cookie_path = "$COOKIE_ROOT/$cookie";
	$krb5cc_path = $self->cookie_auth_krb($args{user},
					      $args{pass},
					      $cookie_path);
	# debug
	debug("login: krb5cc=$krb5cc_path");

	last unless($krb5cc_path);
	
	my($s);
	$s = "$COOKIE_NAME=$cookie; Path=/; Max-Age=$COOKIE_MAX_TIME";
	$s .= "; Secure=1" if( $SECURE_COOKIE );

	if( $req ) {
	    # debug
	    debug("login: Set-Cookie: $s");
	    
	    $req->err_header_out('Set-Cookie' => $s);
	}
	
	$err = 0;
    }
    if( $err ) {
	$err = $self->err();
	unlink($cookie_path);
    }

    return $err;
}

sub destroy_cookie {
    my($self) = shift;
    my($cookie) = @_;
    
    # debug
    debug("destroy_cookie: $COOKIE_ROOT/$cookie");

    unlink("$COOKIE_ROOT/$cookie");
    unlink("$COOKIE_ROOT/$cookie.krb5cc");
}

sub logout_handler {
    my($req) = shift;
    my($self) = Apache::AuthKrb5Afs->new();
    my(%args, $prev, $redirect);
    
    $self->logout();

    my(%args) = $req->args();
    $redirect = $args{'redirect'};

    $prev = $req->prev();
    if( !$redirect &&  $prev ) {
	$redirect = $prev->uri();
    }

    if( !$redirect ) {
	$redirect = "/login";
    }

    $req->status(302);
    $req->err_header_out("Location", $redirect);
    $req->send_http_header();
    return OK;
}

sub logout {
    my($self) = shift;
    my($req) = @_;

    my($req) = Apache->request();
    my($cookie);

    TRY: {
	$cookie ||= $self->get_cookie($req);
	last unless( $cookie );
	
	$req->err_header_out('Set-Cookie' => 
			     "$COOKIE_NAME=; Max-Age=0; Path=/");
	$self->destroy_cookie($cookie);

	$req->user('');
	$req->subprocess_env('AUTH_COOKIE', '');
	$req->subprocess_env('AUTH_COOKIE_PATH', '');
	$ENV{USER} = '';
	$ENV{REMOTE_USER} = '';
	$ENV{HOME} = '';
    }
}

__END__

=head1 NAME

Apache::AuthKrb5Afs - integrated OpenAFS/Krb5 login for Apache

=head1 DESCRIPTION

This mod_perl module lets Apache acquire OpenAFS and Krb5 tokens for
user requests.  So, users can access files and scripts on AFS with
Apache, using their AFS password.  Users can also use DAV to uplaod
and download files to AFS as an alternative to FTP or a local AFS
client.

This has several benefits:

=over 4

=item 

Users can use AFS access control lists instead of .htaccess files to
restrict access to files and scripts.

=item

Users can use DAV as a secure alternative to FTP to access files
in AFS.  DAV works when a local AFS client is not available.

=item

Apache does not need to run as root to assume a user's AFS rights.  No
more suEXEC.

=item

Scripts run with the user's Krb5 and AFS identity.  Since secure login
is built into each request, scripts do not have to implement their own
login/access control mechanism.  Scripts that connect to Kerberos-awar
applications (eg databases like PostgreSQL) can use the web request's
Krb5 ticket for access.

=back

=head1 PREREQUISITES

You must have a working OpenAFS + Krb5 installation.  

You also need Apache with mod_perl and mod_dav.  The included
Makefile.PL can build Apache for you.

AFS user ids must be in the Unix user database.  Getpwuid(afs_uid)
must find the UNIX user name and home directory for the right Unix
user.

This has been developed and tested using Debian GNU/Linux (woody),
openafs-1.2.8, krb5-1.2.4, apache-1.3.29, mod_perl-1.29,
mod_dav-1.0.3-1.3.6, and mod_ssl-2.8.16-1.3.29.  Apache-2.0 does not
work at the time of this writing, due to limitations in mod_perl-1.99.

=head1 HOW IT WORKS

A login script collects a password and user name.  The password is
passed to kinit to get a Krb5 ticket.  The Krb5 ticket is saved in a
browser cookie.  Subsequent requests use the cookie to locate the Krb5
ticket, renews the ticket, and gets AFS tokens from it using aklog.

Here it is step by step:

=over 4

=item

A client accesses an AFS file with Apache.

=item

If the file is protected, Apache throws a 403 error.

=item

Apache redirects 403 errors to a login page.

=item

The login page collects the user's name and password and sends it
through Apache::AuthKrb5Afs->login().

=item

Apache::AuthKrb5Afs uses Auth::Krb5AFS to acquire Krb5 and AFS tokens
with the user's password.

=item

Apache::AuthKrb5Afs saves the Krb5 ticket next to a cookie in a local
cache and returns the cookie's session key to the client.

=item

Note: DAV requests from Windows Explorer ignore cookies and use HTTP
Basic authentication exclusively.  Apache::AuthKrb5Afs will make a
pseudo session key from the client's "Authentication" header and reuse
that to find a cached Krb5 ticket.

=item

The login page redirects the user to the original URL that threw the
403 error.

=item

The next client request sends the cookie.  Apache uses the cookie to
find the cached Krb5 ticket, renews the ticket (with kinit), and
acquires AFS permissions (with aklog).  Apache sets the following
environment variables to indicate sucessful login: REMOTE_USER, USER,
HOME, SHELL, SESKEY, KRB5CCNAME, AUTH_COOKIE, and AUTH_COOKIE_PATH

=item

If the URL was a script, it will execute with the user's AFS
permissions.  The script can check the REMOTE_USER environment
variable to confirm that the user logged in.  The only way REMOTE_USER
will be non-empty is if the user is really authenticated with
kerberos.

If a script requires authentication, it can throw a 403 error to
invoke the Apache::AuthKrb5Afs login mechanism.

=item

Apache's Krb5 ticket can be used with other krb5-aware programs.  For
example, this will allow an Apache request to access a PostgreSQL
database with a user's credentials without passing the user's password
again.

=back

=head1 INSTALLATION

Basically, 

    export HTTPD_DIR=/path/to/apache   # (optional)
    perl Makefile.PL
    make
    make test
    make install

You need a working Apache with mod_perl and mod_dav.  If you don't
have Apache already, the script in "src/build-apache-moddav" will
download and build all these for you and install them into $PWD/usr:

    apache_1.3.29
    mod_perl-1.29
    mod_ssl-2.8.16-1.3.29
    mod_dav-1.0.3-1.3.6   (with patch for OpenAFS)

Mod_dav needed a small patch to handle OpenAFS directories.

After the test works, you can update your local Apache configuration.

=over 4

=item

Add "test/httpd-afs.conf" to your local "httpd.conf"

=item

Install the test/www/login.pl script in your web root and customize it
for your site.

=back

=head1 TESTING

The "test" directory has a minimal httpd.conf that gets Apache
listening with mod_dav under port 8000.

    cd test
    edit httpd-test.init
    ./httpd-test.init start

A shorthand way to run kttpd-test.init and tail the log file is:

    make test INTERACTIVE=1

Now browse http://127.0.0.1:8000/afs.  If your browse a read-protected
AFS directory, you will be redirected to the login page.  If you
browse an AFS directory with DAV you will get a password prompt.

=head1 BUGS

=over 4

=item

As with all authentication schemes, be careful not to send the cookies
unencrypted, or allow unencrypted basic authentication.  All
authenticated traffic should be over HTTPS.

=item

Make sure the Krb5 ticket cache (/tmp/AuthKrb5Afs) is only readable by
the Apache process.

=item

Krb5 tickets are cached in a local temporary directory.  If you use a
cluster of web servers, you should store the krb5 tickets in a shared
AFS directory.

=item

Browsing DAV directories under Windows Explorer is slow.  It looks
like explorer sends one PROPFIND request per directory entry, and the
overhead of each request adds up.

=back

=head1 SEE ALSO

 OpenAFS  - http://www.openafs.org
 Apache   - http://www.apache.org
 mod_dav  - http://www.webdav.org/mod_dav/
 mod_perl - http://perl.apache.org
 bkbox    - http://www.bkbox.com

kinit(1), aklog(1), Apache(3)

=head1 AUTHOR

 Noel Burton-Krahn <noel@bkbox.com>
 www.burton-krahn.com
 Dec 15, 2003
 Copyright (C) 2003 Noel Burton-Krahn <noel@bkbox.com>


=head1 LICENSE

Copyright (C) 2003 Noel Burton-Krahn <noel@bkbox.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
