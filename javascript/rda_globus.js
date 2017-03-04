/***********************************************************************************
 *     Title : rda_globus.js
 *    Author : Thomas Cram (tcram@ucar.edu)
 *      Date : 11/09/2014
 *   Purpose : javascript program to manage RDA Globus shared endpoints.
 * Work File : $DSSWEB/js/rda_globus.js
 * Test File : $DSSWEB/js/rda_globus_test.js
 ***********************************************************************************/

/**
 * requestGlobusInvite - function to add Globus permission to a shared endpoint
 *                       directory and send an e-mail invitation to the user.
 *
 * gtype: Globus transfer type (1 = dsrqst, 2 = dataset share, 3 = custom file list)
 * ridx: dsrqst request index (required for gtype = 1)
 * dsid: Dataset ID (dsnnn.n, required for gtype = 2)
 * grpcnt: Number of groups displayed on file list web interface ()
 *
 */
function requestGlobusInvite(gtype, ridx, dsid, grpcnt) {
   var errmsg = "An error has occurred. Please send this message to rdahelp@ucar.edu for " +
                "assistance. (gtype: " + gtype + " ridx: " + ridx + " dsid: " + dsid + ")";
   if(typeof gtype === "undefined" || gtype < 1 || gtype > 3) {
     alert(errmsg);
   }
   if((typeof ridx !== "undefined") && (typeof dsid !== "undefined")){
     alert(errmsg);
     return;
   }
   if(typeof ridx === "undefined" && typeof dsid === "undefined"){
     alert(errmsg);
     return;
   }
   if(gtype == 1 || gtype == 2) {
     openGlobusWindow(grpcnt, gtype, ridx, dsid, count);
   }
   if(gtype == 3) {
     var count = checkFileSelection(grpcnt);
     if(count === 0) {
       return;
     }
     showGlobusList(gtype, dsid, grpcnt, count);
   }
}

/**
 * open a window for filelist, perl script or csh script
 * gtype: 1 = dsrqst, 2 = dataset share, 3 = custom file list
 */

function openGlobusWindow(grpcnt, gtype, ridx, dsid, count)
{
   var filewin;
   var action;
   var fname;
   var msg;

   if(typeof dsid === "undefined") {
     dsid = document.form.dsid.value;
   }
   fname = "Globus data transfer: ";

   if(gtype == 1) {
      action = "Globus dsrqst";
      ridx = document.form.ridx.value;
      fname += "request ID " + ridx;
   } else if(gtype == 2){
      action = "Globus dataset share";
      fname += dsid;
   } else {
      action = "Globus file transfer";
   }

//   filewin = window.open("", "_blank");
   filewin = window.open("", action, "width=500,height=400,scrollbars=yes,resizable=yes");
   filewin.document.write("<html><head><title>" + fname + "</title>" +
         "<meta charset=\"utf-8\">\n" +
         "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" +
         "<link rel=\"stylesheet\" type=\"text/css\" href=\"/css/newstyle.css\">\n" +
         "<link rel=\"stylesheet\" type=\"text/css\" href=\"/css/bootstrap.rda.css\">\n" +
          "</head>\n<body>\n");

   if(gtype == 1) {
     msg = "transfer your data files";
   }
   if(gtype == 2) {
     msg = "transfer the data files from this dataset (" + dsid + ")";
   }
   
   showGlobusInstructions(filewin, msg, gtype, ridx, dsid);
   
   filewin.document.write("</body></html>\n");
   filewin.document.close();
   filewin.focus();
}

function showGlobusInstructions(win, msg, gtype, ridx, dsid)
{
   win.document.write("<div id=\"load\">\n");
   win.document.write("<p>Click the button labeled 'Request Globus transfer' to \n");
   win.document.write( msg + " via the Globus data transfer service. A Globus user \n");
   win.document.write("account is not required. You may sign into Globus with your RDA \n");
   win.document.write("user e-mail and password by selecting 'NCAR RDA' organizational \n");
   win.document.write("login on the Globus login page, and then enter your RDA e-mail \n");
   win.document.write("login and password.</p>\n");

   win.document.write("<form name=\"globusForm\" action=\"/php/dsglobus.php\" method=\"post\" onsubmit=\"showLoading()\">\n");
   win.document.write("<input type=\"hidden\" name=\"gtype\" value=\"" + gtype + "\">\n");
   if(gtype == 1 && typeof ridx !== "undefined") {
      win.document.write("<input type=\"hidden\" name=\"ridx\" value=\"" + ridx + "\">\n");
   }
   if(gtype == 2 && typeof dsid !== "undefined") {
      win.document.write("<input type=\"hidden\" name=\"dsid\" value=\"" + dsid + "\">\n");
   }
   win.document.write("<p><button type=\"submit\" class=\"btn btn-primary\">Request Globus transfer</button>");
   win.document.write("&nbsp<button type=\"button\" class=\"btn btn-link\" onClick=\"self.close()\">Cancel</button></p>\n");
   win.document.write("</form>\n");
   win.document.write("</div>\n");
}

/** Open form and build array of files selected by user as input parameters to
    dsglobus.php **/

function showGlobusList(gtype, dsid, grpcnt, count)
{
   var i, j, k, fidx;
   var files, checks;
   var limit, grpid;
   var size = document.form.total.value;
   var total = totalSize(size);
   var s = count > 1 ? "s" : "";
   var are = count > 1 ? " are" : " is";
   var sizes, notes;
   var specialist, name;
   var gname;
   var stat = 0;
   var ogidx = 1;
   var showgroup = false;
   var shownote = false;
   var adesc, wpath;
   var html, hidden_input;
   var gindex = document.form.gindex ? document.form.gindex.value : 0;
   var rstat = document.form.rstat ? document.form.rstat.value : null;
   var dfmt = document.form.dfmt ? document.form.dfmt.value : null;
   var cancelurl = document.location.href;

// Open form
   wpath = document.form.wpath.value;
   html = "<form name=\"globusForm\" action=\"/php/dsglobus.php\" method=\"POST\" onsubmit=\"showLoading()\">\n" +
          "<input type=\"hidden\" name=\"gtype\" value=\"" + gtype + "\">\n" + 
          "<input type=\"hidden\" name=\"dsid\" value=\"" + dsid + "\">\n" +
          "<input type=\"hidden\" name=\"directory\" value=\"" + wpath + "/\">\n" +
          "<input type=\"hidden\" name=\"cancelurl\" value=\"" + cancelurl + "\">\n";

   html += "<div id=\"load\">\n";
   html += "<p><h2>File" + s + " selected for RDA dataset " + dsid + "</h2>" +
            "</p>\n<p>You have selected " + count + " file" + s + " (" +
            total + ").\n";

   html += "<p>To transfer these files using the Globus data transfer service, " +
      "select the button labeled <strong>'Globus transfer'</strong> below.  You will be redirected to the " +
      "Globus web app where you will be prompted to select a target endpoint to receive " +
      "the data transfer. Once you have defined a target endpoint, you will be redirected back " +
      "to the RDA website and your data transfer will be submitted.</p>\n" +
      "<p>A Globus user account is not required to use this service. You " +
      "may sign into Globus with your RDA user e-mail and password by selecting the " +
      "'NCAR RDA' organizational login on the Globus login page, and then enter your RDA " +
      "e-mail login and password.</p>\n";

   if(document.form.specialist) {
      specialist = document.form.specialist.value;
      name = document.form.fstname.value + " " + document.form.lstname.value;
   } else {
      specialist = "tcram";
      name = "Thomas Cram";
   }
   html += "<p>Contact <strong>" + specialist + "@ucar.edu (" + name + ")</strong> for further assistance.</p>\n" +
           "<p><button type=\"submit\" class=\"btn btn-primary\">Globus transfer</button>" +
           "&nbsp;<a class=\"btn btn-link\" href=\"javascript:void(0)\" onclick=\"displayDownloadForm(0)\">Cancel</a></p>\n";

// Display table and write selected files to hidden input

   hidden_input = "";
   // check if show local file names / group ids
   for(i = 1; i <= grpcnt; i++) {
      checks = document.form.elements["GRP" + i];
      if(checks === null) {
        continue;
      }
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
   html += "<p>The file" + s + " you have selected" + are + " listed below:</p>\n" +
      "<table class=\"filelist\" style=\"width: 95%\">\n" +
      "<tr class=\"blue-header\">\n" +
      "<th class=\"blue-header\">Index</th>\n" +
      "<th class=\"blue-header\">File name</th>\n" + 
      "<th class=\"blue-header\">Size</th>\n";
   if(showgroup) html += "<th class=\"blue-header\">Group ID</th>\n";
   if(shownote)  html += "<th class=\"blue-header\">Description</th>\n";
   html += "</tr>\n";
   k = 1;
   for(i = 1; i <= grpcnt; i++) {
      checks = document.form.elements["GRP" + i];
      if(checks === null) continue; // should not happen
      files = document.form.elements["FIL" + i];
      sizes = document.form.elements["SIZ" + i];
      gname = eval("document.form.GNAME" + i);
      if(shownote) {
         notes = document.form.elements["NOTE" + i];
      }
      for(j = 0; j < checks.length; j++) {
         if(!checks[j].checked || checks[j].value == -1) continue;
         fidx = parseInt(checks[j].value);
         html += "<tr class=\"zebra\">\n" +
                 "<td class=\"zebra\">" + k++ + "</td>\n" +
                 "<td class=\"zebra\">" + files[fidx].value + "</td>\n" + 
                 "<td class=\"zebra\">" + totalSize(sizes[fidx].value) + "</td>\n";
         if(showgroup) html += "<td class=\"zebra\">" + str_value(gname) + "</td>\n";
         if(shownote)  html += "<td class=\"zebra\">" + str_value(notes[fidx]) + "</td>\n";
         html += "</tr>\n";
         hidden_input += "<input type=\"hidden\" name=\"globusFile[]\" value=\"" + files[fidx].value + "\">\n";
      }
   }
   html += "</table>\n";
   html += hidden_input + "</div>\n</form>\n";
   displayDownloadForm(1);
   document.getElementById("downloadForm").innerHTML = html;
}

function closeAlert(id) {
   var close = document.getElementsByClassName(id);
   var i;

   for (i = 0; i < close.length; i++) {
      close[i].onclick = function() {
         var div = this.parentElement;
         div.style.opacity = "0";
         setTimeout(function(){ div.style.display = "none"; }, 600);
      }
   }
   return;
}

function showLoading() {
   getElementById("load").innerHTML = "<img src=\"images/loader.gif\"></img>";
}