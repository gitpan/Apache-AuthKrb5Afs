#! /usr/bin/perl -w

use Cwd;
use strict;
my($cwd) = getcwd();
my($s, $httpd_dir);

if( $ENV{NO_HTTPD_DIR} ) {
    print("NO_HTTPD_DIR is set, skipping Apache test\n");
}
else {
    # find Apache
    print("Looking for Apache with mod_perl and mod_dav in HTTPD_DIR...\n");
    foreach $s ( $ENV{HTTPD_DIR}, glob("$cwd/usr/apache*"), glob("/usr/local/apache*"), glob("/usr/apache*") ) {
	next unless( $s && -d $s);
	if( $s && (-x "$s/bin/httpd") && (-f "$s/libexec/libdav.so") ) {
	    $httpd_dir = $s;
	    last;
	}
	print("HTTPD_DIR $s exists, but does not contain httpd, mod_perl, or mod_dav\n");
    }
    $s = $httpd_dir;
    if( $s && -d $s ) {
	print("\n",
	      "Found apache in $s.\n",
	      "\n",
	      "If you'd like to use a different Apache, run this script again with HTTPD_DIR like\n",
	      "   HTTPD_DIR=/abs/path/to/apache perl $0\n",
	      "\n",
	      );
    }
    else {
	print("\n",
	      "I couldn't find Apache!\n",
	      "\n",
	      "Would you like me to build Apache for you? [Yn] "
	      );
	$s = <STDIN>;
	chomp($s);
	if( $s eq "" || $s =~ /^y/i ) {
	    print("OK, building Apache using src/build-apache-moddav...\n\n");
	    chdir("src"); 
	    system("./build-apache-moddav"); 
	    $s=$?; 
	    chdir("..");

	    if( $s ) {
		print("Apache build failed! Please try again.\n");
		exit($s);
	    }

	    $s = "$cwd/usr/apache_1.3.29";
	}
    }
    if( ! -d $s ) {
	print("\n",
	      "Failed to find Apache!\n",
	      "\n",
	      "I will build, but not test Apache.\n",
	      "\n", 
	      "Run this script again with if you'd like to test Apache\n",
	      "\n", 
	      "    HTTPD_DIR=/abs/path/to/apache perl $0\n",
	      "\n",
	      "You can also run this script to buikld apache for you:\n",
	      "\n",
	      "    ./build-apache-moddav\n",
	      "\n");
    }
    $ENV{HTTPD_DIR} = $s;
}

use ExtUtils::MakeMaker;
WriteMakefile(
	      'NAME'		=> 'Apache::AuthKrb5Afs',
	      'VERSION_FROM'	=> 'AuthKrb5Afs.pm', # finds $VERSION
	      'PREREQ_PM'		=> {'Auth::Krb5Afs' => 1.0}, 
	      ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
	       (ABSTRACT_FROM => 'AuthKrb5Afs.pm', # retrieve abstract from module
		AUTHOR     => 'Noel Burton-Krahn <noel@bkbox.com>') : ()),
	      
);

unless( $ENV{NO_HTTPD_DIR} ) {
    open(F, ">>Makefile");
    print(F "HTTPD_DIR=$ENV{HTTPD_DIR}\n");
    close(F);
}

