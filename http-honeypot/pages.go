package main

// Canned responses. These deliberately mimic stock software so the honeypot
// blends in with the millions of real, slightly-misconfigured servers on the
// internet. None of them are functional — every credential submitted is logged
// and every login "fails".

const nginxWelcome = `<!DOCTYPE html>
<html>
<head>
<title>NexusAI Developer Platform</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>NexusAI Developer Platform</h1>
<p>Inference APIs, model deployments and usage reporting for approved teams.</p>
<p><a href="/docs">API documentation</a> &middot;
<a href="/login">Sign in</a> &middot; <a href="/status">Service status</a></p>
<p><small>EU production edge &mdash; request access through your team owner.</small></p>
</body>
</html>
`

const nginx404 = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0 (Ubuntu)</center>
</body>
</html>
`

const tomcat401 = `<!doctype html><html lang="en"><head><title>401 Unauthorized</title></head>
<body><h1>401 Unauthorized</h1><p>You are not authorized to view this page.
If you have not changed any configuration files please examine the file
conf/tomcat-users.xml in your installation.</p></body></html>
`

const tomcat403 = `<!doctype html><html lang="en"><head><title>403 Access Denied</title></head>
<body><h1>403 Access Denied</h1><p>Access to the requested resource has been denied.</p></body></html>
`

const wpLogin = `<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<title>Log In &lsaquo; WordPress</title>
</head>
<body class="login">
<div id="login">
<h1><a href="#">WordPress</a></h1>
<form name="loginform" id="loginform" action="wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" value=""></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" value=""></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In"></p>
</form>
</div>
</body>
</html>
`

const phpMyAdmin = `<!DOCTYPE HTML>
<html lang="en" dir="ltr">
<head><meta charset="utf-8"><title>phpMyAdmin</title></head>
<body>
<div class="container">
<a href="#" class="logo">phpMyAdmin</a>
<h1>Welcome to phpMyAdmin</h1>
<form method="post" action="index.php" name="login_form">
<fieldset>
<legend>Log in</legend>
<label for="input_username">Username:</label>
<input type="text" name="pma_username" id="input_username" value="">
<label for="input_password">Password:</label>
<input type="password" name="pma_password" id="input_password" value="">
<input type="submit" name="Go" value="Go">
</fieldset>
</form>
</div>
</body>
</html>
`

const genericLogin = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>NexusAI Account</title></head>
<body>
<h2>Sign in to NexusAI</h2>
<form method="post" action="">
<p><label>Username <input type="text" name="username"></label></p>
<p><label>Password <input type="password" name="password"></label></p>
<p><button type="submit">Sign in</button></p>
</form>
</body>
</html>
`
