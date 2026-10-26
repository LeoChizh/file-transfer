"""The one page the phone sees: an upload form and what has arrived so far."""
import html
import urllib.parse

TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Upload</title>
<style>
  body{font-family:-apple-system,sans-serif;margin:2em;max-width:32em}
  button{padding:.6em 1.2em;font-size:1em}
  li{margin:.2em 0}
</style></head>
<body>
<h2>Send files</h2>
<form method="POST" action="upload" enctype="multipart/form-data">
  <input type="file" name="file" multiple required><br><br>
  <button type="submit">Upload</button>
</form>
<hr>
__CA__
<h3>Files</h3>
<ul>__LISTING__</ul>
</body></html>"""

CA_BLOCK = """<p><a href="ca.pem">Install the certificate</a> once to stop
the warnings: open the link, allow the profile, then Settings &rarr;
General &rarr; VPN &amp; Device Management to install it, and Settings
&rarr; General &rarr; About &rarr; Certificate Trust Settings to turn it
on.</p>"""


def render(names, ca=False):
    """The page listing these file names, as bytes ready to write."""
    if names:
        listing = "".join(
            f'<li><a href="{urllib.parse.quote(n)}">{html.escape(n)}</a></li>'
            for n in names
        )
    else:
        listing = "<li><em>empty</em></li>"
    body = TEMPLATE.replace("__LISTING__", listing)
    return body.replace("__CA__", CA_BLOCK if ca else "").encode("utf-8")
