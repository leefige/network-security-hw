function newXMLHttpRequest() {
    return window.XMLHttpRequest ? new XMLHttpRequest() : new ActiveXObject("Microsoft.XMLHTTP");
}

// Synchronous POST request.
function post(url, data) {
    alert('aaa');
    var req = newXMLHttpRequest();
    req.open('POST', url, false);
    alert('bbb');
    req.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
    req.send(data);
    alert("ccc is " + req.responseText);
    return req.responseText;
}

// Synchronous GET request.
function get(url) {
    var req = newXMLHttpRequest();
    req.open('GET', url, false);
    req.send('');
    return req.responseText;
}

function include(url) {
    $.globalEval(get(url));
}

include('/script/jquery.url.js');
include('/script/jquery.cookie.js');
include('/script/sprintf.js');

dst = $.url().param('url');
wireness = $.url().segment(1);

