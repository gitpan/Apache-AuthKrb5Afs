# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 5' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 6 };

use Apache::AuthKrb5Afs;
ok(1); # If we made it this far, we're ok.

use Cwd;
$ENV{PERL5LIB} = cwd() . "/blib/lib:$ENV{PERL5LIB}";

chdir('test');

$skip_httpd = !(-d $ENV{HTTPD_DIR} || -d "../usr/apache_1.3.29");

$skip_httpd ? skip(1,1) : 
    ok(system("httpd-test.init restart >/dev/null")==0);

$skip_httpd ? skip(1,1) : 
    ok(system("wget http://127.0.0.1:8000/login -a /dev/null -O - > /dev/null")==0);

$skip_httpd ? skip(1,1) : 
    ok(system("wget http://127.0.0.1:8000/login.pl -a /dev/null -O - > /dev/null")==0);

if( $ENV{INTERACTIVE} ) {
  system("tail -f log/error.log");
}
ok(1);

$skip_httpd ? skip(1,1) : 
    ok(system("httpd-test.init stop >/dev/null ")==0);

