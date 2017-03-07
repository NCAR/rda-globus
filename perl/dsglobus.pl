#!/usr/bin/perl -wT
#
##################################################################################
#
#     Title : dsglobus.pl
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 08/14/2014
#   Purpose : Utility program to create and manage shared endpoints to facilitate
#             Globus data transfers from the RDA.
#
# Work File : $DSSHOME/bin/perl/dsglobus.pl*
# Test File : $DSSHOME/bin/perl/dsglobus_test.pl*
#  SVN File : $HeadURL: https://subversion.ucar.edu/svndss/tcram/perl/dsglobus.pl $
#
##################################################################################
use strict;
use Getopt::Long;
use lib "/glade/u/home/rdadata/lib/perl";
use lib "/glade/apps/opt/perlmods/lib/perl5/x86_64-linux-thread-multi";
use lib "/usr/local/lib64";
use MyDBI;
use MyLOG;
use MySubset;
use MyUtil;
use JSON::Parse ':all';

my %MYGLOBUS = (
   user        => 'rda',                          # RDA Globus user name
   ssh         => 'ssh rda@cli.globusonline.org', # Globus CLI ssh command
   host        => 'ncar#datashare',               # Globus host endpoint
   myproxy     => 'myproxy.globusonline.org',     # MyProxy server
   hostdir     => undef,                          # identical to request output directory $rdir
   rqstendpoint => 'rda#data_request',            # Globus shared endpoint for dsrqst transfers
   fileendpoint => 'rda#datashare',               # Globus shared endpoint for general dataset file transfers
   rqstendpointID => 'd20e610e-6d04-11e5-ba46-22000b92c6ec', # UUID of Globus shared endpoint for dsrqst transfers
   fileendpointID => 'db57de42-6d04-11e5-ba46-22000b92c6ec', # UUID of Globus shared endpoint for general dataset file transfers
   datacartendpoint => 'rda#datacart',            # Globus shared endpoint for data cart transfers
   sshkey      => '/.ssh/id_rsa_yslogin1',        # public ssh key linked to rda Globus account
   endpointURL => 'https://www.globus.org/app/'  # URL for shared Globus endpoints
);

my %options = (
   endpoint       => undef,    # Globus shared endpoint
   endpointID     => undef,    # Globus shared endpoint UUID
   addperm        => undef,    # If set, add permission to a shared endpoint
   removeperm     => undef,    # If set, remove permission from a shared endpoint
   resend         => undef,    # If set, re-send Globus share invitation
   path           => undef,    # Path to shared data, relative to the root path of the shared endpoint
   ridx           => undef,    # dsrqst ID
   dsid           => undef,    # dataset ID
   cidx           => undef,    # data cart ID
   order_id       => undef,    # data cart order ID
   email          => undef,    # user e-mail address
   user_identity  => undef,    # user identity (UUID) associated with the user's Globus Auth NCAR RDA alternate identity
   donotnotify    => undef,    # If set, do not send e-mail notification to user when new share is created (default behavior sends notification)
   globus_rid     => undef,    # Globus rule ID for data share permission
   globus_url     => undef     # URL for shared data endpoint
);

my $action;
my ($errmsg, $acl_rule_id);
my ($addPermission, $removePermission);

$| = 1;

# assign ownership of process to rdadata
set_suid($MYLOG{EUID}) if($MYLOG{EUID} != $MYLOG{RUID});

$MYGLOBUS{sshkey} = $MYLOG{DSSHOME} . $MYGLOBUS{sshkey};
$MYLOG{LOGFILE} = "dsglobus.log";

# Set PYTHONPATH environment variable
$ENV{PYTHONPATH} = "/glade/u/apps/opt/python/2.7.7/gnu-westmere/4.8.2/lib/python2.7/site-packages:" .
                   "/glade/u/home/rdadata/lib/python2.7/site-packages:" .
                   "/glade/u/home/tcram/lib/python";

# parse command line input
$action = parse_input("dsglobus");

if($options{removeperm}) {
  remove_endpoint_permission($action);
} elsif($options{addperm} || $options{resend}) {
  remove_endpoint_permission($action) if($options{resend});
  $options{globus_rid} = add_endpoint_permission($action);
  $options{globus_url} = construct_endpoint_url($action);
  update_share_db($action);
} else {
  show_usage("dsglobus");
}

exit 1;

#
# Add permission to a shared endpoint's access control list
#
#   $action = 1   dsrqst shares
#   $action = 2   general share to a dataset directory
#   $action = 3   data cart shares
#
sub add_endpoint_permission{
   my ($action) = @_;
   my ($myrqst, $myshare);
   my ($email, $dsid, $path, $cond);
   my ($ssh_id, $cmd, $stdout, $rule_id, $logmsg, $ridx, $rqstid);
   my ($mycart, $cidx);
 
   if ($action == 1) {
     $ridx = $options{ridx};
     $myrqst = myget("dsrqst", "*", "rindex = $ridx", LOGWRN, __FILE__, __LINE__);
     return mylog("$ridx: Request Index not on file", LGWNEX) if(!$myrqst);
     return mylog("$ridx: Request ID is missing", LGWNEX) if(!$myrqst->{rqstid});   
     $rqstid = $myrqst->{rqstid};
     $options{email} = $myrqst->{email};
     if($myrqst->{globus_rid}) {
       $logmsg = "The Globus permission rule ID " . $myrqst->{globus_rid} . 
                 " has already been created for request $ridx.";
       return mylog($logmsg, LGWNEX);
     }
   } elsif ($action == 2) {
     $email = $options{email};
     $dsid = $options{dsid};
     $cond = "email='$email' AND dsid='$dsid' AND status='ACTIVE'";
     $myshare = myget("goshare", "*", $cond, LOGWRN, __FILE__, __LINE__);
     if($myshare->{globus_rid}) {
       $logmsg = "The Globus permission rule ID " . $myshare->{globus_rid} . 
                 " has already been created for user e-mail $email and dataset " .
                 "$dsid.";
       return mylog($logmsg, LGWNEX);
     }
   } elsif ($action == 3) {
     $cidx = $options{cidx};
     $mycart = myget("dscart", "*", "cartindex=$cidx", LOGWRN, __FILE__, __LINE__);
     return mylog("$cidx: Data cart index not on file", LGWNEX) if(!$mycart);
     return mylog("$cidx: Data cart order ID is missing", LGWNEX) if(!$mycart->{orderid});   
     $options{orderid} = $mycart->{orderid};
     $options{email} = $mycart->{email};
     if($mycart->{globus_rid}) {
       $logmsg = "The Globus permission rule ID " . $mycart->{globus_rid} . 
                 " has already been created for data cart index $cidx.";
       return mylog($logmsg, LGWNEX);
     }
   }
   
   if(!$options{path}) {
     $path = construct_share_path($action, $rqstid);
     $options{path} = $path;
   } else {
     $path = $options{path};
   }
   
   $options{user_identity} = get_user_identity($options{email} . "\@rda.ucar.edu");
   
   $ssh_id =  " -i $MYGLOBUS{sshkey}";
   $cmd = $MYGLOBUS{ssh} . $ssh_id . " acl-add $options{endpoint}$path --perm r --identityid $options{user_identity}";
   $cmd .= " --notify-email $options{email}" if(!$options{donotnotify});

   print "$cmd\n";
   mylog("[add_endpoint_permission] $cmd");
   $stdout = mysystem($cmd, undef, 16, __FILE__, __LINE__);
   print "$stdout\n";

# Parse UUID from stdout (in the form of a 8-4-4-4-12 hexadecimal pattern)  
   if($stdout && $stdout =~ /([\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})/) {
     $rule_id = $1;
     return $rule_id;
   } else {
     $errmsg = "Globus rule ID missing from acl-add stdout";
     mylog($errmsg, LGEREX);
   }
}

#
# Remove permission to a shared endpoint's access control list and delete rule ID from
# the dsrqst record.
# 
sub remove_endpoint_permission{
   my ($action) = @_;
   my ($myrqst, $ridx, $myshare);
   my ($ssh_id, $rule_id, $date, $cond);
   my %record;
   
   $date = curdate();
   
   if ($action == 1) {
     $ridx = $options{ridx};
    # mysystem("update_globus_users.py -n rda#data_request", LGWNEX, 7, __FILE__, __LINE__);
     $myrqst = myget("dsrqst", "*", "rindex = $ridx", LOGWRN, __FILE__, __LINE__);   
     return mylog("$ridx: Request Index is not on file", LGWNEX) if(!$myrqst);
     return mylog("$ridx: Globus rule id is not on file.", LGWNEX) if(!$myrqst->{globus_rid});
     myexec("UPDATE dsrqst SET globus_rid = NULL WHERE rindex=$ridx");
     $rule_id = $myrqst->{globus_rid};
   } elsif ($action == 2) {
    # mysystem("update_globus_users.py -n rda#datashare", LGWNEX, 7, __FILE__, __LINE__);
     $cond = "email='$options{email}' AND dsid='$options{dsid}' AND status='ACTIVE'";
     $myshare = myget("goshare", "*", $cond, LOGWRN, __FILE__, __LINE__);
     return mylog("Globus rule id is not on file for user $options{email} and dataset " .
                  $options{dsid}, LGWNEX) if(!$myshare || !$myshare->{globus_rid});
     %record = (
       delete_date => $date,
       status => "DELETED"
     );
     myupdt("goshare", \%record, $cond, LGEREX, __FILE__, __LINE__);
     $rule_id = $myshare->{globus_rid};
   }
   
   $ssh_id =  " -i $MYGLOBUS{sshkey}";
   mysystem($MYGLOBUS{ssh} . $ssh_id . " acl-remove $options{endpoint} --id $rule_id");

   $options{globus_rid} = undef;
   $options{globus_url} = undef;
}

#
# Add a Globus shared endpoint for sharing RDA data
#
sub add_globus_shared_endpoint {
   my($logact, @locs) = @_;
   push @locs, __FILE__;
   
   mysystem($MYGLOBUS{ssh} . "endpoint-add --sharing=$MYGLOBUS{host}/$MYGLOBUS{hostdir} $MYGLOBUS{endpoint}");
}

#
# Remove a Globus shared endpoint
#
sub remove_globus_shared_endpoint {
   my($logact, @locs) = @_;
   push @locs, __FILE__;
   
   mysystem($MYGLOBUS{ssh} . "endpoint-remove $MYGLOBUS{endpoint}");
}

#
# Construct URL for shared endpoint
# 
sub construct_share_path {
  my ($action, $rqstid) = @_;
  my $path;

  if ($action == 1) {
    return mylog("Request ID is missing", LGWNEX, __FILE__, __LINE__) if(!defined $rqstid);
    # Check if custom download path exists in dsrqst record.  
    $path = "/download.auto/" . $rqstid . "/";
  } elsif ($action == 2) {
    return mylog("Dataset ID is missing", LGWNEX, __FILE__, __LINE__) if(!defined $options{dsid});
    $path = "/" . $options{dsid} . "/";
  } elsif ($action == 3) {
    return mylog("Data cart ID is missing", LGWNEX, __FILE__, __LINE__) if(!defined $options{orderid});
    $path = "/datacart/" . $options{orderid} . "/";
  }
  return $path;
}

#
# Construct URL for shared endpoint
# 
# Examples: 
# https://www.globus.org/app/transfer?origin_id=db57de42-6d04-11e5-ba46-22000b92c6ec&origin_path=%2Fds083.2%2F
# https://www.globus.org/app/transfer?origin_id=d20e610e-6d04-11e5-ba46-22000b92c6ec&origin_path=%2Fdownload.auto%2FABBAOMAR148126%2F
# https://beta.globus.org/app/transfer?origin_id=c71f8c38-c534-11e5-ac97-22000b460624&origin_path=%2F

sub construct_endpoint_url {
  my ($action) = @_;
  
  my ($myrqst, $ridx, $dsid, $ssh_id, $cmd, $stdout, $json);
  my ($origin_id, $origin_path, $endpointURL);
  my $urlhash = "%23";
  my $urlslash = "%2F";
  my ($identity, $add_identity);
  my ($mycart, $cidx);
  
  if ($options{user_identity} ne "") {
    $add_identity = "&add_identity=$options{user_identity}";
  } else {
    $add_identity = "";
  }
  
  if($action == 1) {
    $origin_id = $MYGLOBUS{rqstendpointID};
    $ridx = $options{ridx};
    $myrqst = myget("dsrqst", "*", "rindex = $ridx", LOGWRN, __FILE__, __LINE__);   
    return mylog("$ridx: Request Index not on file", LGWNEX) if(!$myrqst);
    return mylog("$ridx: Request ID is missing", LGWNEX) if(!$myrqst->{rqstid});   
    $origin_path = $urlslash . "download.auto" . $urlslash . $myrqst->{rqstid} . $urlslash;
  } elsif ($action == 2) {
    $origin_id = $MYGLOBUS{fileendpointID};
    $dsid = $options{dsid};
    $origin_path = $urlslash . $dsid . $urlslash;
  } elsif ($action == 3) {
    $origin_id = $MYGLOBUS{cartendpointUUID};
    $cidx = $options{cidx};
    $mycart = myget("dscart", "*", "cartindex = $cidx", LOGWRN, __FILE__, __LINE__);   
    return mylog("$cidx: Data cart index not on file", LGWNEX) if(!$mycart);
    return mylog("$cidx: Data cart order ID is missing", LGWNEX) if(!$mycart->{orderid});   
    $origin_path = $urlslash . "datacart" . $urlslash . $mycart->{orderid} . $urlslash;
  }  
  $endpointURL = $MYGLOBUS{endpointURL} . "transfer?origin_id=". $origin_id . "&origin_path=" . $origin_path . $add_identity;
  return $endpointURL;
}

#
# Get a user's identity (UUID) assigned by the Globus Auth API.  Input argument $user can 
# be one of the following:
#		GlobusID (Globus primary identity): in the form of user@globusid.org
#		NCAR RDA alternate identity       : in the form of user@domain.com@rda.ucar.edu, where user@domain.com is the user's RDA e-mail login
#		E-mail identity                   : in the form of user@domain.com
# 
sub get_user_identity {
  my ($user) = @_;
  my ($ssh_id, $cmd, $stdout, $identity_details, $identity);
  
  $ssh_id =  " -i $MYGLOBUS{sshkey}";
  $cmd = $MYGLOBUS{ssh} . $ssh_id . " identity-details $user";
  $stdout = mysystem($cmd, undef, 16, __FILE__, __LINE__);
  if($stdout && $stdout =~ /([\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})/) {
    $identity_details = parse_json($stdout);
    $identity = $identity_details->{id};
  } else {
     $identity = "";
  }
  return $identity;
}

#
# Add or update Globus share information in RDADB
# 
sub update_share_db {
  my ($action) = @_;
  my ($myuser, $cond, $date, $ridx, $cidx);
  my %record;

  $date = curdate();
  
  if($action == 1) {
    $ridx = $options{ridx};
    %record = (
      globus_rid => $options{globus_rid},
      globus_url => $options{globus_url}
    );
    myupdt("dsrqst", \%record, "rindex=$ridx", LGEREX, __FILE__, __LINE__) if($record{globus_url} && $record{globus_rid});
  } elsif ($action == 2) {
    $cond = "email = '$options{email}' AND end_date IS NULL";
    $myuser = myget("ruser", "id", $cond, LOGWRN, __FILE__, __LINE__);
    return mylog("User $options{email} not on file in DB.", LGWNEX) if(!$myuser);
    %record = (
      globus_rid => $options{globus_rid},
      globus_url => $options{globus_url},
      email => $options{email},
      user_id => $myuser->{id},
      username => undef,
      request_date => $date,
      source_endpoint => $options{endpoint},
      dsid => $options{dsid},
      acl_path => $options{path},
      status => 'ACTIVE'
    );
    myadd("goshare", \%record, LGEREX, __FILE__, __LINE__) if($record{globus_url} && $record{globus_rid});
  } elsif($action == 3) {
    $cidx = $options{cidx};
    %record = (
      globus_rid => $options{globus_rid},
      globus_url => $options{globus_url}
    );
    myupdt("dscart", \%record, "cartindex=$cidx", LGEREX, __FILE__, __LINE__) if($record{globus_url} && $record{globus_rid});
  }
  return;
}

#
# Parse command line input
#
sub parse_input {
  my ($aname) = @_;
  
  my ($us, $ridx, $dsid, $action);
  my ($addperm, $removeperm, $resend, $help, $path, $endpoint, $email, $donotnotify);

  $action = 0;
  
   if(@ARGV) {
      cmdlog("$aname @ARGV");
   } else {
      show_usage($aname);
   }

  $us = ($MYLOG{HOSTNAME} eq 'evans') || ($MYLOG{HOSTNAME} eq 'bross') || ($MYLOG{HOSTNAME} eq 'castle') ? "_" : "";
  Getopt::Long::Configure("bundling_override", "ignore" . $us . "case_always");

  if(!GetOptions("ri|RequestIndex=i" => \$ridx,
  		 "ds|Dataset=s" => \$dsid,
  		 "ci|CartIndex" => \$cidx,
                 "ap|AddPermission" => \$addperm,
                 "rp|RemovePermission" => \$removeperm,
                 "rs|ResendInvitation" => \$resend,
                 "dp|DownloadPath=s" => \$path,
                 "ep|Endpoint=s" => \$endpoint,
                 "em|Email=s" => \$email,
                 "ne|DoNotNotify" => \$donotnotify,
                 "h|help" => \$help)) {
    show_usage($aname);
  }

  show_usage($aname) if($help);
  if( ($addperm && $removeperm) || ($addperm && $resend) || ($removeperm && $resend) ) {
    $errmsg = "Only one action option is allowed: -ap, -rp, or -rs";
    mylog($errmsg, LGEREX, __FILE__, __LINE__);
  }
  if(($ridx && $dsid) || ($ridx && $cidx) || ($dsid && $cidx)) {
    $errmsg = "Please specify only one of: dsrqst index (-ri) or dataset ID (-ds), not both.";
    mylog($errmsg, LGEREX, __FILE__, __LINE__);
  }

  $options{addperm} = $addperm if($addperm);
  $options{removeperm} = $removeperm if($removeperm);
  $options{resend} = $resend if($resend);
  $options{donotnotify} = $donotnotify if($donotnotify);

  if ($ridx) {
    $options{ridx} = $ridx;
    $options{endpoint} = $MYGLOBUS{rqstendpoint};
    $options{endpointID} = $MYGLOBUS{rqstendpointID};
    $action = 1;
  } elsif ($dsid) {
    return mylog("Please specify the dataset id as dsnnn.n or nnn.n", LGEREX, __FILE__, __LINE__) if($dsid !~ /^(ds){0,1}\d+\.\d+$/i);
    return mylog("User e-mail address is missing.  Please specify with the -em flag.", LGEREX, __FILE__, __LINE__) if(!$email);
    $dsid = "ds" . $dsid if ($dsid =~ /^\d+\.\d+$/);
    $options{dsid} = $dsid;
    $options{email} = $email;
    $options{endpoint} = $MYGLOBUS{fileendpoint};
    $options{endpointID} = $MYGLOBUS{fileendpointID};
    $action = 2;
  } elsif ($cidx) {
    $options{cidx} = $cidx;
    $options{endpoint} = $MYGLOBUS{datacartendpoint};
    $action = 3;
  } else {
    $errmsg = "Please specify either the dsrqst index (-ri) for a subset request, or 
               the dataset ID (-ds) and user e-mail address (-em) for a general Globus 
               share to a dataset.";
    return mylog($errmsg, LGEREX, __FILE__, __LINE__);
  }
  
# Check for leading and trailing forward slash '/' in $path
  if($path) {
    $path = "/" . $path if(substr($path, 0, 1) ne "/");
    $path .= "/" if(substr($path, -1) ne "/");
    $options{path} = $path;
  }
  return $action;
}

#
# List information about active endpoints (endpoint-list)
#

#
# Create hard links to RDA static files
#

#
# Purge hard links from a shared endpoint
#

