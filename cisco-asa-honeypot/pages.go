package main

// Static response bodies. The small, purely structural ones (wrong_url.html,
// logon_redir.html) are ported verbatim from t3chn0m4g3/ciscoasa_honeypot's
// asa/ directory -- confirmed via direct fetch (#414). The larger branded
// assets upstream ships (logon.html, portal.css, win.js, header images,
// several KB each) are deliberately not reproduced byte-for-byte here: the
// signal this decoy exists to capture is server-side (which paths get hit,
// and the CVE-2018-0101 host-scan-reply payload), not exact visual parity
// with a real ASA login page, so a much smaller placeholder login page
// fills the same structural role.

const ciscoWrongURLPage = `<html>
<body>
<br>
<center><b>Wrong URL.</b></center>
</body>
</html>
`

const ciscoLogonRedirPage = `<html>
<head>
<script>
document.location.replace("/+CSCOE+/logon.html?"+
"a0=86"+
"&a1="+
"&a2="+
"&a3=1&reason=1");
</script>
</head>
</html>
`

const ciscoRootRedirectPage = `<html><script>document.location.replace("/+CSCOE+/logon.html")</script></html>
`

const ciscoLogonPage = `<!DOCTYPE html>
<html>
<head><title>SSL VPN Service</title></head>
<body>
<form method="post" action="/+webvpn+/index.html">
<input type="text" name="username">
<input type="password" name="password">
<input type="submit" value="Login">
</form>
</body>
</html>
`

const ciscoLogonFailurePage = `<!DOCTYPE html>
<html>
<head><title>SSL VPN Service</title></head>
<body>
Login failed.
</body>
</html>
`
