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
use MyDBI;
use MyLOG;
use MySubset;
use MyUtil;

my %MYGLOBUS = (
   user        => 'rda',                          # RDA Globus user name
   ssh         => 'ssh rda@cli.globusonline.org', # Globus CLI ssh command
   host        => 'ncar#datashare',               # Globus host endpoint
   myproxy     => 'myproxy.globusonline.org',     # MyProxy server
   hostdir     => undef,                          # identical to request output directory $rdir
   rqstendpoint => 'rda#data_request',            # Globus shared endpoint for dsrqst transfers
   fileendpoint => 'rda#datashare',               # Globus shared endpoint for general dataset file transfers
#   rqstendpoint => 'd20e610e-6d04-11e5-ba46-22000b92c6ec', # UUID of Globus shared endpoint for dsrqst transfers
#   fileendpoint => 'db57de42-6d04-11e5-ba46-22000b92c6ec', # UUID of Globus shared endpoint for general dataset file transfers
   datacartendpoint => 'rda#datacart',            # Globus shared endpoint for data cart transfers
   sshkey      => '/.ssh/id_rsa_yslogin1',        # public ssh key linked to rda Globus account
   endpointURL => 'https://www.globus.org/xfer/StartTransfer?origin=rda'  # URL for shared Globus endpoints
#   endpointURL => 'https://www.globus.org/app/'  # URL for shared Globus endpoints
);

my %options = (
   endpoint       => undef,    # Globus shared endpoint
   addperm        => undef,    # If set, add permission to a shared endpoint
   removeperm     => undef,    # If set, remove permission from a shared endpoint
   resend         => undef,    # If set, re-send Globus share invitation
   path           => undef,    # Path to shared data, relative to the root path of the shared endpoint
   ridx           => undef,    # dsrqst ID
   dsid           => undef,    # dataset ID
   email          => undef,    # user e-mail address
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
   
   if ($action == 1) {
     $ridx = $options{ridx};
     $myrqst = myget("dsrqst", "*", "rindex = $ridx", LOGWRN, __FILE__, __LINE__);
     return mylog("$ridx: Request Index not on file", LGWNEX) if(!$myrqst);
     return mylog("$ridx: Request ID is missing", LGWNEX) if(!$myrqst->{rqstid});   
     $rqstid = $myrqst->{rqstid};
     $options{email} = $myrqst->{email};
     if($myrqst->{globus_rid}) {
       $logmsg = "The Globus permission rule ID " . $myrqst->{globus_rid} . 
                 " has already been created for request $ridx. Use option -rs to " .
                 "resend the invitation.";
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
                 "$dsid. Use option -rs to resend the invitation.";
       return mylog($logmsg, LGWNEX);
     }
   } elsif ($action == 3) {
     # [Need code here to query Globus access rule ID for this endpoint]
   }
   
   if(!$options{path}) {
     $path = construct_share_path($action, $rqstid);
     $options{path} = $path;
   } else {
     $path = $options{path};
   }
   
   # Query user's Globus username
   # $globus_user = get_globus_username();
   
   $ssh_id =  " -i $MYGLOBUS{sshkey}";
#   $cmd = $MYGLOBUS{ssh} . $ssh_id . " acl-add $options{endpoint}$path --perm r --identityusername $options{email} --notify-email $options{email}";
   $cmd = $MYGLOBUS{ssh} . $ssh_id . " acl-add $options{endpoint}$path --perm=r --email=$options{email}";
   
   print "$cmd\n";
   
   $stdout = mysystem($cmd, undef, 16, __FILE__, __LINE__);
   
   print "$stdout\n";

# Parse UUID from stdout (in the form of a 8-4-4-4-12 hexadecimal pattern)  
#   if($stdout && $stdout =~ /([\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})/) {
   if($stdout && $stdout =~ /(\d+)$/) {
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
     mysystem("update_globus_users.py -n rda#data_request", LGWNEX, 7, __FILE__, __LINE__);
     $myrqst = myget("dsrqst", "*", "rindex = $ridx", LOGWRN, __FILE__, __LINE__);   
     return mylog("$ridx: Request Index is not on file", LGWNEX) if(!$myrqst);
     return mylog("$ridx: Globus rule id is not on file.", LGWNEX) if(!$myrqst->{globus_rid});
     myexec("UPDATE dsrqst SET globus_rid = NULL WHERE rindex=$ridx");
     $rule_id = $myrqst->{globus_rid};
   } elsif ($action == 2) {
     mysystem("update_globus_users.py -n rda#datashare", LGWNEX, 7, __FILE__, __LINE__);
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
  
  my ($myrqst, $ridx, $dsid);
  my ($urlpath, $endpointURL);
  my ($endpoint_prefix, $endpoint_suffix);
  my $urlhash = "%23";
  my $urlslash = "%2F";
  
  ($endpoint_prefix, $endpoint_suffix) = split('#', $options{endpoint});

  if($action == 1) {
    $origin_id = $MYGLOBUS{rqstendpoint};
    $ridx = $options{ridx};
    $myrqst = myget("dsrqst", "*", "rindex = $ridx", LOGWRN, __FILE__, __LINE__);   
    return mylog("$ridx: Request Index not on file", LGWNEX) if(!$myrqst);
    return mylog("$ridx: Request ID is missing", LGWNEX) if(!$myrqst->{rqstid});   
    $urlpath = $urlhash . $endpoint_suffix . $urlslash . "download.auto" . 
               $urlslash . $myrqst->{rqstid} . $urlslash;
#    $origin_path = $urlslash . "download.auto" . $urlslash . $myrqst->{rqstid} . $urlslash;
  } elsif ($action == 2) {
    $origin_id = $MYGLOBUS{fileendpoint};
    $dsid = $options{dsid};
    $urlpath = $urlhash . $endpoint_suffix . $urlslash . $dsid . $urlslash;
#    $origin_path = $urlslash . $dsid . $urlslash;
  }  
  $endpointURL = $MYGLOBUS{endpointURL} . $urlpath;
#  $endpointURL = $MYGLOBUS{endpointURL} . "transfer?origin_id=". $origin_id . "&origin_path=" . $origin_path;

  return $endpointURL;
}

#
# Add or update Globus share information in RDADB
# 
sub update_share_db {
  my ($action) = @_;
  my ($myuser, $cond, $date, $ridx);
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
  }
  return;
}

#
# Parse command line input
#
sub parse_input {
  my ($aname) = @_;
  
  my ($us, $ridx, $dsid, $action);
  my ($addperm, $removeperm, $resend, $help, $path, $endpoint, $email);

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
                 "ap|AddPermission" => \$addperm,
                 "rp|RemovePermission" => \$removeperm,
                 "rs|ResendInvitation" => \$resend,
                 "dp|DownloadPath=s" => \$path,
                 "ep|Endpoint=s" => \$endpoint,
                 "em|Email=s" => \$email,
                 "h|help" => \$help)) {
    show_usage($aname);
  }

  show_usage($aname) if($help);
  if( ($addperm && $removeperm) || ($addperm && $resend) || ($removeperm && $resend) ) {
    $errmsg = "Only one action option is allowed: -ap, -rp, or -rs";
    mylog($errmsg, LGEREX, __FILE__, __LINE__);
  }
  if($ridx && $dsid) {
    $errmsg = "Please specify either the dsrqst index (-ri) or dataset ID (-ds), not both.";
    mylog($errmsg, LGEREX, __FILE__, __LINE__);
  }

  $options{addperm} = $addperm if($addperm);
  $options{removeperm} = $removeperm if($removeperm);
  $options{resend} = $resend if($resend);

  if ($ridx) {
    $options{ridx} = $ridx;
    $options{endpoint} = $MYGLOBUS{rqstendpoint};
    $action = 1;
  } elsif ($dsid) {
    return mylog("Please specify the dataset id as dsnnn.n or nnn.n", LGEREX, __FILE__, __LINE__) if($dsid !~ /^(ds){0,1}\d+\.\d+$/i);
    return mylog("User e-mail address is missing.  Please specify with the -em flag.", LGEREX, __FILE__, __LINE__) if(!$email);
    $dsid = "ds" . $dsid if ($dsid =~ /^\d+\.\d+$/);
    $options{dsid} = $dsid;
    $options{email} = $email;
    $options{endpoint} = $MYGLOBUS{fileendpoint};
    $action = 2;
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

