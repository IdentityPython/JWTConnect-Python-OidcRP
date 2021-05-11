#!/usr/bin/env python3
import importlib
import sys

pre = """
<!DOCTYPE html>

<html>
<head>
    <meta charset="UTF-8">
    <title>pyoidc RP</title>
</head>
<body>
<h1>OP by UID</h1>
<p>
    You can perform a login to an OP's by using your unique identifier at the OP.
    A unique identifier is defined as your username@opserver, this may be equal to an e-mail address.
    A unique identifier is only equal to an e-mail address if the op server is published at the same
    server address as your e-mail provider.
</p>
<form action="rp" method="get">
  <h2>Start sign in flow</h2>
  <h3>By entering your unique identifier:</h3>
  <input type="text" id="uid" name="uid" class="form-control" placeholder="UID" autofocus>  
  <h3><em>Or</em> you can chose one of the preconfigured OpenID Connect Providers</h3>
  <select name="iss">
  {select}
  </select>
  <button type="submit">Start</button>
</form>
</body>
</html>
"""

config = importlib.import_module(sys.argv[1])

option = []
for key in config.CLIENTS.keys():
    if key == '':
        option.append('<option value=""></option>')
    else:
        option.append('<option value="{}">{}</option>'.format(key, key))

_html = pre.format(select='\n'.join(option))
print(_html)