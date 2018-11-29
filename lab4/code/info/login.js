/* Configurable */
var pre_roam_id = [ "2002", "2003", "2005" , "2006" ];
var pre_roam_renew_id = [ "3002", "3003", "3005", "3006" ];
var pre_roam_interval = 500; // in millisecond
var pre_roam_max_retry = 10;
var pre_roam_renew_interval = 300000; // in millisecond

var pre_roam_id_loaded = [];
var pre_roam_retried = 0;
var pre_roam_redirect = "/";
var pre_roam_done = false;

function login_ongoing() {
	// $("body").html("<div><h2>ÕýÔÚµÇÂ¼£¬ÇëÉÔºò...</h2></div>");
	$("head")
			.html(
					"<style>#loading{margin:260px auto 0;padding:0;text-align:center;overflow:hidden;zoom:1;}#loading img{margin:0 auto;}</style>");
	$("body")
			.html(
					"<div id='loading'><img src='/style/images/loading2.gif'/><br /><br />&nbsp;&nbsp;ÕýÔÚµÇÂ¼£¬ÇëÉÔºò...</div>");
}

function login_responded() {
	pre_roam_redirect = login_redirect;
	if (login_result == '1') {
		pre_roam();
		setInterval("login_finished()", pre_roam_interval);
	} else {
		login_failed();
	}
}

function pre_roam() {
	for (var i = 0; i < pre_roam_id.length; i++) {
		var j = pre_roam_id[i];
		var iframe = document.createElement("iframe");
		iframe.name= "iframe_pre_roam";
		iframe.id = "iframe_pre_roam" + j;
		iframe.src = "/minichan/roamaction.jsp?mode=local&id=" + j;
		iframe.style.display = "none";
		iframe.width = "0";
		iframe.height = "0";
		iframe.marginwidth = "0";
		iframe.marginheight = "0";
		iframe.frameborder = 0;
		if (iframe.attachEvent){
		    iframe.attachEvent("onload", function(){
		    	pre_roam_onload(this);
			});
		} else {
    		iframe.onload = function(){
		    	pre_roam_onload(this);
    		};
		document.body.appendChild(iframe);
		}
	}
}

function pre_roam_old() {
	for (var i = 0; i < pre_roam_id.length; i++) {
		var j = pre_roam_id[i];
		$("body")
				.append(
						"<iframe id='pre_roam_"
								+ j
								+ "' src='/minichan/roamaction.jsp?mode=local&id="
								+ j
								+ "' onload='pre_roam_onload(this)' width='0' height='0' marginwidth='0' marginheight='0' frameborder='no'></iframe>");
	}
}

function login_finished() {
	if (pre_roam_done) {
		return;
	}
	if (pre_roam_id_loaded.length == pre_roam_id.length
			|| pre_roam_retried >= pre_roam_max_retry) {
		if (pre_roam_done) {
			return;
		}
		pre_roam_done = true;
		redirect(pre_roam_redirect);
	}
	pre_roam_retried++;
}

function pre_roam_onload(iframe) {
	pre_roam_id_loaded.push(iframe.id);
}

function login_failed() {
	redirect(pre_roam_redirect);
}

function redirect(target) {
	window.location.replace(target);
}

function pre_roam_renew() {
	setInterval("pre_roam_renew_do()", pre_roam_renew_interval);
}

function pre_roam_renew_do() {
	for (var i = 0; i < pre_roam_renew_id.length; i++) {
		var j = pre_roam_renew_id[i];
		$("body")
				.append(
						"<iframe id='pre_roam_renew_"
								+ j
								+ "' src='/minichan/roamaction.jsp?mode=local&id="
								+ j
								+ "' onload='pre_roam_renew_onload(this)' width='0' height='0' marginwidth='0' marginheight='0' frameborder='no'></iframe>");
	}
}

function pre_roam_renew_onload(iframe) {
	$('iframe#' + iframe.id).remove();
}
