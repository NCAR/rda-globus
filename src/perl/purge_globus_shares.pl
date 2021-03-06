#!/usr/bin/perl -wT
#
##################################################################################
#
#     Title : purge_globus_shares.pl
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 07/18/2016
#   Purpose : Purge stale Globus shares.
#
# Work File : $DSSHOME/bin/perl/purge_globus_shares.pl*
# Test File : $DSSHOME/bin/perl/purge_globus_shares_test.pl*
#    Github : 
#
##################################################################################
use strict;
use lib "/glade/u/home/rdadata/lib/perl";
use MyDBI;
use MyLOG;
use MyUtil;

my $myrec;
my ($myrecs, $mytasks, $myuser);
my ($sharecnt, $taskcnt);
my ($offset, $then, $i, $err, $cmd);
my ($email, $completion_time);

$MYLOG{LOGPATH} = "/glade/scratch/tcram/logs/globus";
$MYLOG{LOGFILE} = "purge_globus_shares.log";

# Get date from ~six months (180 days) ago
$offset = -120;
$then = offset_date($offset);
mylog("Purging ACLs prior to: $then", LOGWRN);

# Query active Globus shares greater than six months old
$myrecs = mymget("goshare", "email,dsid", "request_date < '$then' AND status='ACTIVE' AND source_endpoint='rda#datashare' ORDER BY request_date ASC");
$sharecnt = $myrecs ? @{$myrecs->{email}} : 0;
mylog("Number of active ACLs: $sharecnt", LOGWRN);
if($sharecnt > 0) {
  for($i = 0; $i<$sharecnt; $i++) {
    $email = $myrecs->{email}[$i];
    # Skip if DSS group member
    $myuser = myget("wuser", "email,org_type", "email='$email'");
#    print "$myuser->{email}\n" if($myuser);
    next if($myuser && $myuser->{org_type} eq 'DSS');
    $mytasks = mymget("gotask", "email,completion_time", "email='$email' AND source_endpoint='rda#datashare' ORDER BY completion_time DESC");
    $taskcnt = $mytasks ? @{$mytasks->{email}} : 0;
    if($taskcnt == 0 || $mytasks->{completion_time}[0] lt $then) {
      mylog("task count: $taskcnt", LOGWRN);
      $completion_time = $mytasks ? $mytasks->{completion_time}[0] : "n/a";
      mylog("completion time: $completion_time", LOGWRN);
      mylog("$offset days ago: $then", LOGWRN);
      $cmd = "dsglobus -rp -ds $myrecs->{dsid}[$i] -em $myrecs->{email}[$i]";
      mylog("$cmd", LOGWRN);
      mysystem($cmd, LGWNEX, 7, __FILE__, __LINE__);
    }
  }
}
