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
use lib "/glade/u/home/rdadata/perl5/lib/perl5";
use lib "/usr/local/lib64";
use MyDBI;
use MyLOG;
use Date::Manip;

my $myrec;
my ($myrecs, $mytasks, $myuser);
my ($sharecnt, $taskcnt);
my ($then, $sixMonthsAgo, $i, $err, $cmd);
my ($email, $completion_time);

# Get date from six months ago
$sixMonthsAgo = DateCalc("today", "-6 months", \$err);
$then = UnixDate("$sixMonthsAgo", "%Y-%m-%d%n");
print "$then\n";

# Query active Globus shares greater than six months old
$myrecs = mymget("goshare", "email,dsid", "request_date < '$then' AND status='ACTIVE' ORDER BY request_date ASC");
$sharecnt = $myrecs ? @{$myrecs->{email}} : 0;
print "share count: $sharecnt\n";
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
      print "task count: $taskcnt\n";
      $completion_time = $mytasks ? $mytasks->{completion_time}[0] : "n/a";
      print "completion time: $completion_time\n";
      print "six months ago: $then\n";
      $cmd = "dsglobus -rp -ds $myrecs->{dsid}[$i] -em $myrecs->{email}[$i]";
      print "$cmd\n\n";
      mysystem($cmd, LGWNEX, 7, __FILE__, __LINE__);
    }
  }
}
