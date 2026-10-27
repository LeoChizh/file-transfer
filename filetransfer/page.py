"""The one page the phone sees: an upload form and what has arrived so far."""
import html
import urllib.parse

TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>File drop</title>
<style>
  :root{--bg:#f2f3f7;--card:#fff;--text:#1c1c1e;--muted:#6b6b72;
        --line:#e3e4ea;--accent:#0a84ff;--accent-text:#fff}
  @media (prefers-color-scheme:dark){
    :root{--bg:#000;--card:#1c1c1e;--text:#f2f2f7;--muted:#9a9aa1;
          --line:#2c2c2e;--accent:#0a84ff}
  }
  *{box-sizing:border-box}
  body{margin:0;padding:1.25rem 1rem 2rem;background:var(--bg);
       color:var(--text);font:16px/1.4 -apple-system,system-ui,"Segoe UI",
       Roboto,sans-serif}
  main{max-width:34rem;margin:0 auto}
  h1{font-size:1.6rem;margin:.2rem 0 1rem}
  h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;
     color:var(--muted);margin:1.6rem .25rem .5rem}
  .card{background:var(--card);border-radius:14px;padding:1rem;
        box-shadow:0 1px 2px rgba(0,0,0,.06)}
  input[type=file]{width:100%;font-size:1rem;color:var(--muted);
        padding:1.1rem .8rem;border:2px dashed var(--line);
        border-radius:12px;background:transparent}
  input[type=file]::file-selector-button{margin-right:.8rem;border:0;
        border-radius:8px;padding:.6rem 1rem;font-size:1rem;
        background:var(--line);color:var(--text)}
  button{display:block;width:100%;margin-top:.9rem;padding:.85rem;
         border:0;border-radius:12px;font-size:1.05rem;font-weight:600;
         background:var(--accent);color:var(--accent-text)}
  button:active{opacity:.8}
  ul{list-style:none;margin:0;padding:0}
  li{border-top:1px solid var(--line)}
  li:first-child{border-top:0}
  li a{display:block;padding:.75rem .25rem;color:var(--accent);
       text-decoration:none;word-break:break-all}
  li em{display:block;padding:.75rem .25rem;color:var(--muted)}
  .note{font-size:.9rem;color:var(--muted);margin:0}
  .note a{color:var(--accent)}
</style></head>
<body><main>
<h1>File drop</h1>
<form class="card" method="POST" action="upload" enctype="multipart/form-data">
  <input type="file" name="file" multiple required>
  <button type="submit">Upload</button>
</form>
__CA__
<h2>Files</h2>
<ul class="card">__LISTING__</ul>
</main></body></html>"""

CA_BLOCK = """<h2>Certificate</h2>
<p class="card note"><a href="ca.pem">Install the certificate</a> once to stop
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
