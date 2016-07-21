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

session_start();
include_once("MyRqst.inc");

manage_acl();

function manage_acl() {

   global $MYLOG;

   $msg = "initiate a Globus file transfer";
   $mfunc = "bmessage";

   $email = cookie_email($msg, true, $mfunc);
   if(empty($email)) return;

   if(empty($_POST["gtype"])) return pmessage("Missing Globus request gtype (1=dsrqst, 2=dataset share, 3=custom file list)", true);
   $gtype = escape_input_string($_POST["gtype"]);
   if($gtype == 1) {
     acl_dsrqst($msg, $gtype, $email);
   } elseif ($gtype == 2) {
     acl_dataset($msg, $gtype, $email);
   } elseif ($gtype == 3) {
     acl_datacart($msg, $gtype, $email);
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
   bmessage("You may now transfer your data using Globus at the URL <a href=\"" . 
            $datashare["globus_url"] . "\">" . $datashare["globus_url"] . "</a>.<br /> From the Globus " .
            "website, please select 'NCAR RDA' from the list of organizational logins " .
            "and then enter your RDA e-mail address " .
            "<span style=\"font-weight: bold\">(" . $email . ")</span> and " .
            "password to log in.");
}

/**
 * Manage ACLs for custom file lists, and also for a prototype data cart.
 */

function acl_datacart($msg, $gtype, $email) {

   $mfunc = "bmessage";

   $unames = get_ruser_names($email, 5);
   $unames["rid"] = strtoupper(convert_chars($unames["lstname"]));

   # create data cart order record
   $nidx = new_datacart_id();
   $mycart["orderid"] = $unames["rid"] . $nidx;
   $mycart["email"] = $email;
/**   $mycart["size_cart"] = ; */
/**   $mycart["fcount"] = ; */
   $mycart["date_order"] = curdate();
   $mycart["time_order"] = curtime();
   $mycart["date_purge"] = adddate($mycart["date_order"], 5);
   $mycart["time_purge"] = $mycar["time_order"];
   
   $cidx = myadd("dscart", $mycart, true, true);   

   if($nidx != $cidx) { # reset order ID only if it is different
      $mycart["orderid"] = $record["orderid"] = $unames["rid"] . $cidx;
      myupdt("dscart", $record, "cartindex = $cidx");
   }

# Create hard links to data files.  Update size_cart and fcount in dscart table when ready.
# Store as hidden input?

   $cmd = escapeshellcmd('dsglobus -ap -ci ' . $cidx);
   $info = globus_cli_cmd($cmd);
   $order = datacart_record($msg, $cidx, $mfunc);
   bmessage("You may now transfer your data using Globus at the URL <a href=\"" . 
            $order["globus_url"] . "\">" . $order["globus_url"] . "</a>.<br /> From the Globus " .
            "website, please select 'NCAR RDA' from the list of organizations " .
            "and then enter your RDA e-mail address " .
            "<span style=\"font-weight: bold\">(" . $rqst["email"] . ")</span> and " .
            "password to log in.");
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
 * get a single record for a data cart order, given the $email and $cidx
 */
 
function datacart_record($msg, $cidx = 0, $mfunc = "pmessage") {
   if(!$cidx) {
      if(empty($_POST["cidx"])) {
         if($msg) $mfunc("Data cart order index is missing.");
         return null;
      }
      $cidx = escape_input_string($_POST["cidx"]);
   }
   $cond = "cartindex=$cidx";
   $datacart = myget("dscart", "*", $cond, FALSE);

   if(empty($datacart)) {
     return null;
   } else {
     return $datacart;
   }
}

/**
 * find a unique request name/ID from given user last name
 * by appending (existing maximum rindex + 1) 
 */
function new_datacart_id() {

   $myrec = myget("dscart", "MAX(cartindex) maxid");
   if($myrec) {
      return ($myrec["maxid"] + 1);
   } else {
      return 0;
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

/**
 * Function to display a list of files selected by a user and initiate POST request
 * to Globus Browse Endpoint API to select a target endpoint.

 *** CODE BELOW NEEDS TO BE CONVERTED FROM JAVASCRIPT ***

 */

function showDataCartList {

   if(ftype == "Web") {
      win.document.write("<form name=\"form\" action=\"/dsglobus.php\" method=\"post\" onsubmit=\"showLoading()\">\n");
   } else {
      win.document.write("A Globus transfer can only be requested for web-downloadable files.\n");
   }
 
     filewin.document.write("<p>Click the button labeled 'Request Globus transfer' to \n");
     filewin.document.write( msg + " via the Globus data transfer service. You will \n");
     filewin.document.write("redirected to the Globus web app where you will be prompted \n");
     filewin.document.write("to select the destination endpoint of your data transfer.  \n");
     filewin.document.write("A Globus user account is not required to use this service. \n");
     filewin.document.write("You may sign into Globus with your RDA user e-mail and password \n");
     filewin.document.write("by selecting the 'NCAR RDA' organizational login on the Globus \n");
     filewin.document.write("login page.</p>\n");   

   win.document.write("<input type=\"hidden\" name=\"gtype\" value=\"" + gtype + "\">\n");
   win.document.write("<input type=\"hidden\" name=\"dsid\" value=\"" + dsid + "\">\n");
   win.document.write("<p><h2>" + ftype + " File" + s + " Selected For '" + dsid +
            "'</h2></p>\n<p>" + count + " file" + s + ", total " +
            total + ", " + are + " selected.\n");

   wpath = document.form.wpath.value;
   win.document.write("<input type=\"hidden\" name=\"directory\" value=\"" + wpath + "/\">\n");
   win.document.write("Click the <b>'Download Selected'</b> button to " +
                      "directly download the selected files as a single tar file.</p>\n");
   win.document.write("<p><input type=\"submit\" value=" +
                      "\"Download Selected Files As A Tar File\"></p>\n");
   stat = 2;
   win.document.write("</p>\n");         

   if(document.form.specialist) {
      specialist = document.form.specialist.value;
      name = document.form.fstname.value + " " + document.form.lstname.value;
   } else {
      specialist = "tcram";
      name = "Thomas Cram";
   }
   win.document.write("<p>Contact " + specialist + "@ucar.edu (" + name + ") for further assistance.</p>\n");

   // check if show local file names / group ids
   for(i = 1; i <= grpcnt; i++) {
      checks = document.form.elements["GRP" + i];
      if(checks == null) continue;
      gname = eval("document.form.GNAME" + i);
      notes = document.form.elements["NOTE" + i];
      if(gname || notes) {
         for(j = 0; j < checks.length; j++) {
            if(checks[j].checked && checks[j].value >= 0) {
               fidx = parseInt(checks[j].value);
               if(notes && !shownote && notes[fidx].value) shownote = true;
               if(gname && !showgroup && i != ogidx) showgroup = true;
               ogidx = i;
            }
         }
      }
      if(showgroup && shownote) break;
   }
   win.document.write("<p>File" + s + " selected" + are + " listed below:\n");
   win.document.write("<p><table class=\"filelist\" cellspacing=0 cellpadding=2 bgcolor=\"#e1eaff\">\n");
   win.document.write("<tr class=\"flcolor0\"><th class=\"thick-border\">File Name</th>\n");
   win.document.write("<th class=\"thick-border\">Size</th>\n");
   if(showgroup) win.document.write("<th class=\"thick-border\">GROUP ID</th>\n");
   win.document.write("<th class=\"thick-border\">INDEX</th>\n");
   if(shownote) win.document.write("<th class=\"thick-border\">Description</th>\n");
   win.document.write("</tr>\n");
   k = 1;
   for(i = 1; i <= grpcnt; i++) {
      checks = document.form.elements["GRP" + i];
      if(checks == null) continue; // should not happen
      files = document.form.elements["FIL" + i];
      sizes = document.form.elements["SIZ" + i];
      gname = eval("document.form.GNAME" + i);
      sizes = document.form.elements["SIZ" + i];
      if(shownote) {
         notes = document.form.elements["NOTE" + i];
      }
      for(j = 0; j < checks.length; j++) {
         if(!checks[j].checked || checks[j].value == -1) continue;
         fidx = parseInt(checks[j].value);
         win.document.write("<tr><td class=\"thin-border\">" + files[fidx].value + "</td>\n");
         win.document.write("<td class=\"thin-border\" align=\"right\">" + totalSize(sizes[fidx].value) + "</td>\n");
         if(showgroup) win.document.write("<td class=\"thin-border\">" + str_value(gname) + "</td>\n");
         win.document.write("<td class=\"thin-border\" align=\"right\">" + k++ + "</td>\n");
         if(shownote) {
            win.document.write("<td class=\"thin-border\">" + str_value(notes[fidx]) + "</td>\n");
         }
         win.document.write("</tr>\n");
         if(stat == 2) {
            win.document.write("<input type=\"hidden\" name=\"file\" value=\"" + 
                               files[fidx].value + "\">\n");
         }
      }
   }
   win.document.write("</table></p>\n");
}