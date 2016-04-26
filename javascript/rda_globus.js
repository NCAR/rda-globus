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
   if(typeof gtype === 'undefined' || gtype < 1 || gtype > 3) {
     alert(errmsg);
   }
   if((typeof ridx !== 'undefined') && (typeof dsid !== 'undefined')){
     alert(errmsg);
     return;
   }
   if((typeof ridx === 'undefined' && typeof dsid === 'undefined')){
     alert(errmsg);
     return;
   }
   openGlobusWindow(grpcnt, gtype);
}

/**
 * open a window for filelist, perl script or csh script
 * gtype: 1 = dsrqst, 2 = dataset share, 3 = custom file list
 */

function openGlobusWindow(grpcnt, gtype, ridx, dsid)
{
   var filewin;
   var ftype;
   var action;
   var fname;
   var count;
   var ridx;

   if(count == 0) return;
   
   ftype = document.form.ftype.value;
   if(typeof dsid === 'undefined') {
     dsid = document.form.dsid.value;
   }
   fname = "Globus data transfer: ";
   
   if(gtype == 1) {
      action = 'Globus dsrqst';
      ridx = document.form.ridx.value;
      fname += 'request ID ' + ridx;
   } else if(gtype == 2){
      action = 'Globus dataset share';
      fname += dsid;
   } else {
      count = checkFileSelection(grpcnt);
      action = 'Globus custom file list';
      fname += dsid + ' custom file list';
   }

   filewin = window.open("", action, "width=750,height=600,scrollbars=yes,resizable=yes");
   filewin.document.write("<html><head><title>" + fname + "</title></head><body>\n");

   if(gtype == 1) {
     var msg = "transfer your data files";
   }
   if(gtype == 2 || gtype == 3) {
     var msg = "transfer the data files from this dataset (" + dsid + ")";
   }
   filewin.document.write("<div id=\"load\">\n");
   filewin.document.write("<p>Click the button labeled 'Request Globus transfer' to \n");
   filewin.document.write( msg + " via the Globus data transfer service. A Globus user \n");
   filewin.document.write("account is not required. You may sign into Globus with your RDA \n");
   filewin.document.write("user e-mail and password by selecting 'NCAR RDA' organizational \n");
   filewin.document.write("login on the Globus login page, and then enter your RDA e-mail \n");
   filewin.document.write("login and password.</p>\n");      
   filewin.document.write("</div>\n");

   if(gtype == 3 && grpcnt > 0) {
      showGlobusList(filewin, dsid, fname, grpcnt, count, ftype);
   } else {
      filewin.document.write("<form name=\"globusForm\" action=\"/php/dsglobus.php\" method=\"post\" onsubmit=\"showLoading()\">\n");
      filewin.document.write("<input type=\"hidden\" name=\"gtype\" value=\"" + gtype + "\">\n");
      if(gtype == 1 && typeof ridx !== 'undefined') {
        filewin.document.write("<input type=\"hidden\" name=\"ridx\" value=\"" + ridx + "\">\n");
      }
      if(gtype == 2 && typeof dsid !== 'undefined') {
        filewin.document.write("<input type=\"hidden\" name=\"dsid\" value=\"" + dsid + "\">\n");
      }
   }

   filewin.document.write("<p><input type=\"submit\" value=\"Request Globus transfer\">");
   filewin.document.write("&nbsp<input type=\"button\" onClick=\"self.close()\" value=\"Cancel\"></p>\n");
   filewin.document.write("</form>\n");   
   filewin.document.write("</body></html>\n");
   filewin.document.close();
   filewin.focus();
}

function showGlobusList(win, dsid, grpcnt, count, ftype)
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
   var gindex = document.form.gindex ? document.form.gindex.value : 0;
   var rstat = document.form.rstat ? document.form.rstat.value : null;
   var dfmt = document.form.dfmt ? document.form.dfmt.value : null;

   if(ftype == "Web") {
      win.document.write("<form name=\"form\" action=\"/dsglobus.php\" method=\"post\" onsubmit=\"showLoading()\">\n");
   } else {
      win.document.write("A Globus transfer can only be requested for web-downloadable files.\n");
   }
 
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

function showLoading() {
   getElementById("load").innerHTML = "<img src=\"images/loader.gif\"></img>";
}