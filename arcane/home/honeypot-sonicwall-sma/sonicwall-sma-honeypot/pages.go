package main

// workPlaceLoginPage is the pre-auth Work Place portal a real SMA1000
// presents at its root -- the entry point the CVE-2026-83548 SSRF chain
// starts from. No version banner, matching citrix-honeypot's own choice:
// nothing here is tied to a specific firmware build worth inventing.
const workPlaceLoginPage = `<!DOCTYPE html>
<html><head><title>SonicWall Work Place</title></head>
<body class="workplace-login">
<div id="login">
<h1>Work Place</h1>
<form method="post" action="/cgi-bin/welcome/welcome.cgi">
<label for="username">Username</label>
<input type="text" id="username" name="username">
<label for="password">Password</label>
<input type="password" id="password" name="password">
<button type="submit">Log In</button>
</form>
</div>
</body></html>
`

// amcHopPage is the synthetic internal-AMC surface served back once a
// request has been classified as the CVE-2026-83548 SSRF-shaped relay
// (#3033): a real Work Place -> AMC SSRF would land the attacker's next
// request against the Appliance Management Console's own Struts-style
// ".action" routes. "/cgi-bin/amc/rollbackConfirm.action" is not invented --
// it is the literal path from ET sid:2071214 (CVE-2026-15410, a different
// CVE, already loaded on this fleet's Suricata, see
// docs/research/3011-sonicwall-cve.md) -- reused here purely as an
// authentic AMC route name to make this synthetic surface worth attacking,
// not as a claim about CVE-2026-83549's own request shape, which no public
// PoC has confirmed.
const amcHopPage = `<!DOCTYPE html>
<html><head><title>SonicWall Appliance Management Console</title></head>
<body>
<h1>Appliance Management Console</h1>
<form method="post" action="/cgi-bin/amc/rollbackConfirm.action">
<input type="hidden" name="hotfix" value="">
<button type="submit">Confirm</button>
</form>
</body></html>
`
