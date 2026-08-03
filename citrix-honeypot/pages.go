package main

// Response bodies, ported verbatim from t3chn0m4g3/CitrixHoneypot's
// responses/ directory (login.html, 403.html, smb.conf) -- confirmed via
// direct fetch of the upstream repo (#414). The "gold star" reward page for
// failed traversal attempts is deliberately not ported: it's disabled by
// default upstream (struggle_check = False) and exists purely to reward an
// attacker whose client already sanitized the "/../" out of its request, a
// cosmetic feature with no detection value of its own.

const citrixLoginPage = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta http-equiv="Pragma" content="no-cache" />
<title>Citrix Login</title>
</head>
<body class="ns_login_body">
<div id="ns_user_pass_section">
    <div class="ns_grid_text user_name">
        <span>User Name</span>

        <label for="username" style="display: none;">User Name</label>
        <input type="text" id="username" name="username" class="login_input" onfocus=1>
    </div>

    <div class="ns_grid_text login_password">
        <span>Password</span>

        <label for="password" style="display: none;">Password</label>
        <input type="password" name="password" id="password" class="login_input">
    </div>
        <div style="display:none">
            <label for="eula-accepted" style="display: none;">EULA</label>
            <input type="checkbox" name="eula" id="eula-accepted" value="TRUE">
        </div>
        <div class="login_button_cell">
            <label for="url" style="display: none;">URL</label>
            <input type="hidden" name="url" id="url" value="">

            <label for="timezone_offset" style="display: none;">Timezone Offset</label>
            <input type="hidden" name="timezone_offset" id="timezone_offset" value="">

            <button type="submit" class="login_button rdx_blue_button"><span id="logintext">Log On</span><span id="loadingdots"></span></button>
        </div>
</div>
</body>
</html>
`

// citrix403Page has "{url}" replaced with the requested path at serve time,
// matching upstream's own string substitution exactly.
const citrix403Page = `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access {url}
on this server.<br />
</p>
</body></html>
`

const citrixSmbConf = `[global]
                encrypt passwords = yes
                name resolve order = lmhosts wins host bcast
`
