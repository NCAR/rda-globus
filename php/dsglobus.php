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
     return pmessage("Globus request gtype not valid (1=dsrqst, 2=dataset share)", true);
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
     if(empty($_POST["resend"])) {
       $message = "A Globus share permission has already been created for this data request. " .
                "Please check your e-mail account <span style=\"font-weight: bold\">" . 
                 $rqst["email"] . "</span> for a data share invitation from Globus. If " .
                 "you wish to resend the invitation, click the 'Resend invitation' " .
                 "button.";
       return resendForm($message, $gtype, $ridx, null, null);
     } else {
       $cmd = escapeshellcmd('dsglobus -rs -ri ' . $ridx);
     }
   } else {
     $cmd = escapeshellcmd('dsglobus -ap -ri ' . $ridx);
   }
   $info = globus_cli_cmd($cmd);
   bmessage("A new Globus data share invitation has been sent to your e-mail address " .
            "<span style=\"font-weight: bold\">(" . $rqst["email"] . ")</span>. Please " .
            "follow the instructions in the e-mail message to download your data via " .
            "Globus.");
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
     if(empty($_POST["resend"])) {
       $message = "A Globus share permission has already been created for this dataset. " .
                "Please check your e-mail account <span style=\"font-weight: bold\">" . 
                 $email . "</span> for a data share invitation from Globus. If " .
                 "you wish to resend the invitation, click the 'Resend invitation' " .
                 "button.";
       return resendForm($message, $gtype, null, $dsid, $email);
     } else {
       $cmd = escapeshellcmd('dsglobus -rs -ds ' . $dsid . ' -em ' . $email);
     }
   } else {
     $cmd = escapeshellcmd('dsglobus -ap -ds ' . $dsid . ' -em ' . $email);
   }
   $info = globus_cli_cmd($cmd);
   bmessage("A new Globus data share inivitation has been sent to your e-mail address " .
            "<span style=\"font-weight: bold\">(" . $email . ")</span>. Please " .
            "follow the instructions in the e-mail message to download your data via " .
            "Globus.");
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
          "<input type=\"hidden\" name=\"resend\" value=\"true\">\n" . 
          "<p><input type=\"submit\" value=\"Resend invitation\">&nbsp;" .
          "<input type=\"button\" value=\"Cancel\" onClick=\"self.close()\">" . 
          "</p></form></body></html>\n";
    } elseif ($gtype == 2) {
     echo "<html><head><title>Globus data transfer</title></head><body>\n" .
          "<form name=\"globusForm\" action=\"/php/dsglobus.php\" method=\"post\">" .
          "<p>$message</p>\n " .
          "<input type=\"hidden\" name=\"gtype\" value=\"" . $gtype . "\">\n" . 
          "<input type=\"hidden\" name=\"dsid\" value=\"" . $dsid . "\">\n" . 
          "<input type=\"hidden\" name=\"resend\" value=\"true\">\n" . 
          "<p><input type=\"submit\" value=\"Resend invitation\">&nbsp;" .
          "<input type=\"button\" value=\"Cancel\" onClick=\"self.close()\">" . 
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
      if(strpos($path, $MYLOG[DSSHOME]) === false) {
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