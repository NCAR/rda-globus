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
 * gtype: Globus transfer type (1 = dsrqst, 2 = dataset share)
 * ridx: dsrqst request index (required for gtype = 1)
 * dsid: Dataset ID (dsnnn.n, required for gtype = 2)
 *
 */
function requestGlobusInvite(gtype, ridx, dsid) {
   var errmsg = "An error has occurred. Please send this message to rdahelp@ucar.edu for " + 
                "assistance. (gtype: " + gtype + " ridx: " + ridx + " dsid: " + dsid + ")";
   if(typeof gtype === 'undefined' || gtype < 1 || gtype > 2) {
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
   win = window.open("", "Globus data transfer invitation", "width=500,height=400,scrollbars=yes,resizable=yes");
   doc = win.document;
   doc.write("<html><head><title>Globus data transfer</title></head><body>\n");
   if(gtype == 1) {
     var msg = "transfer your data files";
   }
   if(gtype == 2) {
     var msg = "transfer the data files from this dataset (" + dsid + ")";
   }
   doc.write("<div id=\"load\">\n");
   doc.write("<p>Click the button labeled 'Request Globus transfer' to \n");
   doc.write( + msg + " via the Globus data transfer service. A Globus user \n");
   doc.write("account is not required. If you have a Globus user account, you \n");
   doc.write("may sign into Globus with your RDA user name and password by \n");
   doc.write("selecting the 'alternate identity' link on the Globus login page \n");
   doc.write("and selecting the 'NCAR RDA' identity provider.</p>\n");      
   doc.write("</div>\n");

   doc.write("<form name=\"globusForm\" action=\"/php/dsglobus.php\" method=\"post\" onsubmit=\"showLoading()\">\n");
   doc.write("<input type=\"hidden\" name=\"gtype\" value=\"" + gtype + "\">\n");
   if(gtype == 1 && typeof ridx !== 'undefined') {
     doc.write("<input type=\"hidden\" name=\"ridx\" value=\"" + ridx + "\">\n");
   }
   if(gtype == 2 && typeof dsid !== 'undefined') {
     doc.write("<input type=\"hidden\" name=\"dsid\" value=\"" + dsid + "\">\n");
   }
   doc.write("<p><input type=\"submit\" value=\"Request Globus transfer\">");
   doc.write("&nbsp<input type=\"button\" onClick=\"self.close()\" value=\"Cancel\"></p>\n");
   doc.write("</form>\n");

   doc.write("</body></html>\n");
   doc.close();
   win.focus();
}

function showLoading() {
   getElementById("load").innerHTML = "<img src=\"images/loader.gif\"></img>";
}