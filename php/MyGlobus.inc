<?php
################################################################################
#
#     Title: MyGlobus.inc
#    Author: Thomas Cram (tcram@ucar.edu)
#      Date: 10/19/2016
#   Purpose: PHP script defining endpoint IDs and other information required
#            to manage the Globus shared endpoints
#
# Test File: $DSSWEB/php/inc/MyGlobus_test.inc
# Work File: $DSSWEB/php/inc/MyGlobus.inc
#
################################################################################
#

$token_file = "/glade/u/home/rdadata/dssdb/tmp/.globus/globus.transfer-token";
$token_fh = fopen($token_file, "r");
$gotoken = fread($token_fh, filesize($token_file));
fclose($token_fh); 

$MYGLOBUS = array(
   "TOKEN" => $gotoken,
   "BASE_URL" => "https://transfer.api.globusonline.org/v0.10",
   "DATASHARE_ENDPOINT_ID" => "db57de42-6d04-11e5-ba46-22000b92c6ec",
   "DATASHARE_ENDPOINT_BASE" => "/glade2/collections/rda/data/",
   "DATAREQUEST_ENDPOINT_ID" => "d20e610e-6d04-11e5-ba46-22000b92c6ec",
   "DATAREQUEST_ENDPOINT_BASE" => "/glade2/collections/rda/transfer/"
);

?>