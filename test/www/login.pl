#! /usr/bin/perl

local($^W) = 0;
print("Content-Type: text/html\n\n");

if( $ENV{REMOTE_USER} ) {
    print("<h1>Welcome, $ENV{REMOTE_USER}</h1>",
	  "<a href=$ENV{AUTHKRB5AFS_LOGOUT_HANDLER}>Click here to log out</a>\n");
    exit 0;
}

if( $ENV{REDIRECT_AUTHKRB5AFS_REDIRECT} ) {
    print("<h1>You must log in to access that page</h1>\n");
}
else {
    print("<h1>Welcome, Please Log In</h1>\n");
}

print <<EOF

<form action="$ENV{AUTHKRB5AFS_LOGIN_HANDLER}" method=post>
<div color=red>$ENV{REDIRECT_AUTHKRB5AFS_ERR}</div>

<div color=red>$ENV{REDIRECT_AUTHKRB5AFS_ERR_USER}</div>
User: <input type=text name=user value='$ENV{AUTHKRB5AFS_USER}'><br>

<div color=red>$ENV{REDIRECT_AUTHKRB5AFS_ERR_PASS}</div>
Pass: <input type=password name=pass value=''><br>

<input type=hidden name=redirect value='$ENV{REDIRECT_AUTHKRB5AFS_REDIRECT}'>
<input type=submit name=login value='Log In'><br>
</form>

EOF
;

foreach $k (sort keys(%ENV)) {
    print("ENV{$k} = $ENV{$k}<br>\n");
}

