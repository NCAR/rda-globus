<?php
################################################################################
#
#     Title : dsglobus.php
#    Author : Thomas Cram, tcram@ucar.edu
#      Date : 11/05/2014
#   Purpose : PHP script program to add read permission to a Globus shared endpoint. 
#
# Work File : $DSSWEB/php/dsglobus.php
#  SVN File : 
#
################################################################################

include_once("MyRqst.inc");

manage_acl();

function manage_acl() {

   global $MYLOG;

   $msg = "initiate a Globus file transfer";
   $mfunc = "bmessage";

   $email = cookie_email($msg, true, $mfunc);
   if(empty($email)) return;

   if(empty($_POST["gtype"])) return pmessage("Missing Globus request gtype (1=dsrqst, 2=dataset share)", true);
   $gtype = escape_input_string($_POST["gtype"]);
   if($gtype == 1) {
     acl_dsrqst($msg, $gtype, $email);
   } elseif ($gtype == 2) {
     acl_dataset($msg, $gtype, $email);
   } else {
     return pmessage("Globus request gtype ". $gtype . " not valid (1=dsrqst, 2=dataset share)", true);
   }

}

/**
 * Manage ACLs for dsrqst.
 */

function acl_dsrqst($msg, $gtype, $email) {

   $mfunc = "bmessage";
   if(empty($_POST["ridx"])) return pmessage("Missing request index", true);
   $ridx = escape_input_string($_POST["ridx"]);
   $rqst = request_record($msg, $ridx, $mfunc);
   if(empty($rqst)) return;
   
   $rstr = request_type($rqst["rqsttype"]) . " request $ridx from RDA dataset $rqst[dsid]";
   $unames = get_ruser_names($rqst["email"]);
   $uname = "$unames[name] ($rqst[email])";
   $rstr .= " for $uname";

   if($rqst["status"] == "P") {
      return bmessage("$rstr has been purged. A Globus data transfer cannot be initiated.", true);
   } elseif($rqst["status"] != "O" && $rqst["status"] != "H") {
      return bmessage("The status of $rstr is " . request_status($rqst["status"]) .
                      " and not online. A Globus data transfer cannot be initiated at this time.", true);
   }
   if(strcasecmp($rqst["email"], $email) &&
      !(preg_match("/^(.+)@mail\.ucar\.edu$/", $rqst["email"], $match) &&
        $email == "$match[1]@ucar.edu")) {
        return bmessage("$email: you are not the original requester of $rstr, " .
                      "and do not have permission to initiate a Globus data transfer.");
   }
   if(!empty($rqst["globus_rid"])) {
     if(!empty($rqst["globus_url"])) {
       $message = "Please go to <a href=\"" . $rqst["globus_url"] . "\">" . $rqst["globus_url"] . 
                "</a> to transfer your data using Globus.  From the Globus website, you may sign in " .
                "with your RDA e-mail login <span style=\"font-weight: bold\">" . 
                 $rqst["email"] . "</span> and password by selecting 'NCAR RDA' from " .
                "the list of organizations. A Globus account is not required to use this " .
                "service.";
       return resendForm($message, $gtype, $ridx, null, null);
     } else {
       $cmd = escapeshellcmd('dsglobus -rs -ri ' . $ridx);
     }
   } else {
     $cmd = escapeshellcmd('dsglobus -ap -ri ' . $ridx);
   }
   $info = globus_cli_cmd($cmd);
   $rqst = request_record($msg, $ridx, $mfunc);
   bmessage("You may now transfer your data using Globus at the URL <a href=\"" . 
            $rqst["globus_url"] . "\">" . $rqst["globus_url"] . "</a>.<br /> From the Globus " .
            "website, please select 'NCAR RDA' from the list of organizations " .
            "and then enter your RDA e-mail address " .
            "<span style=\"font-weight: bold\">(" . $rqst["email"] . ")</span> and " .
            "password to log in.");
}

/**
 * Manage ACLs for dataset shares.
 */

function acl_dataset($msg, $gtype, $email) {

   $mfunc = "bmessage";
   if(empty($_POST["dsid"])) return pmessage("Missing dataset ID (dsnnn.n)", true);
   $dsid = escape_input_string($_POST["dsid"]);
   
   $datashare = dataset_share_record($msg, $email, $dsid, $mfunc);
   
   if(!empty($datashare)) {
     if(!empty($datashare["globus_url"])) {
       $message = "Please go to <a href=\"" . $datashare["globus_url"] . "\">" . 
                $datashare["globus_url"] . 
                "</a> to transfer your data using Globus.  From the Globus website, you may sign in " .
                "with your RDA e-mail login <span style=\"font-weight: bold\">" . 
                 $email . "</span> and password by selecting 'NCAR RDA' from " .
                "the list of organizations. A Globus account is not required to use this " .
                "service.";
       return resendForm($message, $gtype, null, $dsid, $email);
     } else {
       $cmd = escapeshellcmd('dsglobus -rs -ds ' . $dsid . ' -em ' . $email);
     }
   } else {
     $cmd = escapeshellcmd('dsglobus -ap -ds ' . $dsid . ' -em ' . $email);
   }
   $info = globus_cli_cmd($cmd);
   $datashare = dataset_share_record($msg, $email, $dsid, $mfunc);
   bmessage("You may now transfer your data using Globus at the URL ".
            "<p><a href=\"" . $datashare["globus_url"] . "\">" . 
            $datashare["globus_url"] . "</a>.</p>" .
            "<p>From the Globus website, please select 'NCAR RDA' from the list of " .
            "organizational logins and then enter your RDA e-mail address " .
            "<span style=\"font-weight: bold\">(" . $email . ")</span> and password to " .
            "log in.</p>" .
            "<p><span style=\"font-style: italic\">Note:</span> this Globus data share " .
            "will remain active for six months, and will be then be deleted unless you " .
            "initiate a data transfer within the most recent six months.</p>");
}

/**
 * get dataset share record for a given $email and $dsid, use $_POST["dsid"] if 
 * $dsid = 0
 */
 
function dataset_share_record($msg, $email, $dsid = 0, $mfunc = "pmessage") {
   if(!$dsid) {
      if(empty($_POST["dsid"])) {
         if($msg) $mfunc("Dataset ID is missing.");
         return null;
      }
      $dsid = escape_input_string($_POST["dsid"]);
   }
   $cond = "email = '$email' AND dsid='$dsid' AND status='ACTIVE'";
   $datashare = myget("goshare", "*", $cond, FALSE);

   if(empty($datashare)) {
     return null;
   } else {
     return $datashare;
   }
}

/**
 * Show HTML message with the user option of re-sending the Globus share invitation.
 */

function resendForm($message, $gtype, $ridx=0, $dsid=0, $email) {
   if($gtype == 1) {
     echo "<html><head><title>Globus data transfer</title></head><body>\n" .
          "<form name=\"globusForm\" action=\"/php/dsglobus.php\" method=\"post\">" .
          "<p>$message</p>\n " .
          "<input type=\"hidden\" name=\"gtype\" value=\"" . $gtype . "\">\n" . 
          "<input type=\"hidden\" name=\"ridx\" value=\"" . $ridx . "\">\n" . 
          "<p><input type=\"button\" value=\"Cancel\" onClick=\"self.close()\">" . 
          "</p></form></body></html>\n";
    } elseif ($gtype == 2) {
     echo "<html><head><title>Globus data transfer</title></head><body>\n" .
          "<form name=\"globusForm\" action=\"/php/dsglobus.php\" method=\"post\">" .
          "<p>$message</p>\n " .
          "<input type=\"hidden\" name=\"gtype\" value=\"" . $gtype . "\">\n" . 
          "<input type=\"hidden\" name=\"dsid\" value=\"" . $dsid . "\">\n" . 
          "<p><input type=\"button\" value=\"Cancel\" onClick=\"self.close()\">" . 
          "</p></form></body></html>\n";    
    }
}

/**
 * Function to run a cli command.
 */

function globus_cli_cmd($cmd) {

   global $MYLOG;
   
   $spec = array(
      0 => array("pipe", "r"),   # STDIN
      1 => array("pipe", "w"),   # STDOUT
      2 => array("pipe", "w")    # STDERR
   );

   if(strpos($cmd, '/') === false) {
      $path = getenv('PATH');
      if(strpos($path, $MYLOG['DSSHOME']) === false) {
         $path .= ":$MYLOG[DSSHOME]/bin";
         putenv("PATH=$path");
      }
   }

   $proc = proc_open("$cmd", $spec, $pipes);
   if(!is_resource($proc)) {
      return pmessge("$cmd: error executing command", true);
   }
   fwrite($pipes[0], $rinfo);
   fclose($pipes[0]);

   $out = stream_get_contents($pipes[1]);
   fclose($pipes[1]);
   if($out) mylog(E_NOTICE, $out);
    
   $err = stream_get_contents($pipes[2]);
   fclose($pipes[2]);
   proc_close($proc);

   if($err) return pmessage($err, true);   

   return true;
}