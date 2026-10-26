# file-transfer

Tiny HTTPS file-drop server. Upload files from an iPhone (Safari) to a Linux or Windows machine over the LAN. No app, no cloud, no account.

## Layout

```
file-transfer/
  filetransfer/
    cli.py         argument parsing, the QR code, what gets printed
    server.py      the HTTPS server and its one request handler
    addresses.py   which address of this machine to advertise
    certs.py       the local CA and the server certificate
    names.py       safe, non-colliding names for uploaded files
    page.py        the upload form and file listing
    tokens.py      the shared secret in every URL
  pyproject.toml   installable, provides the `file-transfer` command
  ca.pem           local authority -- the one to install on the phone
  ca-key.pem       its key (created automatically, mode 600)
  cert.pem         server certificate, signed by the CA
  key.pem          its key (created automatically, mode 600)
  token.txt        current secret used in the URL (rewritten on every start)
  uploads/         files land here
  tests/           unit tests
  .venv/           python venv
```

## Setup

**Linux / macOS**

```sh
git clone https://github.com/LeoChizh/file-transfer.git
cd file-transfer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/LeoChizh/file-transfer.git
cd file-transfer
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

That is all the setup there is. The first run creates the certificate, the
key, the token and the upload folder; there is nothing to configure.

## Run

```sh
python -m filetransfer     # python3 on Linux
```

Installing it (`pip install -e .`) also gives a `file-transfer` command that
works from any directory.

Everything it writes --- `cert.pem`, `key.pem`, `token.txt`, `uploads/` ---
lands in the current directory, so run it from wherever you want the files.
Leave it running; stop it with Ctrl-C. Options:

```
--port PORT     port to listen on (default 8443)
--dir PATH      where files land (default ./uploads)
--host ADDRESS  address for the URL and the certificate, instead of guessing
--cert PATH     --key PATH    --token-file PATH
```

It prints the URL, including the secret token:

```
[*] https://192.168.35.9:8443/Xk3...Qw/
[*] saving into /home/user/file-transfer/uploads
```

The LAN address comes first. If the machine has more than one local address
--- Docker, a second NIC --- the others are listed below it as `or ...`, and
all of them are in the certificate, so any of them works.

A VPN does not change the URL: the addresses are read off the interfaces, not
from whichever route happens to win, so a tunnel address never pushes out the
LAN one. Tunnel addresses are not served at all, and stay out of the
certificate, because they come and go and every change to the certificate
means reinstalling it on the phone:

```
[*] https://192.168.35.9:8443/Xk3...Qw/
[*] not serving tunnel 10.99.0.2 (keeps the cert stable; FILE_TRANSFER_HOST overrides)
```

The exception is a machine with nothing else: if every address is a tunnel,
the tunnel is served after all, so there is still a URL. To pick the address
by hand --- including a tunnel that was skipped:

```sh
python -m filetransfer --host 192.168.35.9    # or $FILE_TRANSFER_HOST
```

A QR code of the URL is drawn above it: scan it with the iPhone camera instead of typing the token. (Needs the `qrcode` package; without it only the URL is printed.)

Open exactly that URL. Anything without the token returns 404, for uploads and downloads alike. The token is regenerated on every start, so old URLs and bookmarks stop working after a restart; scan the new QR code. `token.txt` just holds the current one.

## Upload from iPhone

1. Connect to the same Wi-Fi as the server.
2. In Safari, open the URL printed on startup.
3. Cert warning: **Show Details** → **visit this website** (once per device).
4. Pick one or more files → **Upload**. They appear in `uploads/`.

## The .local name

If something on the machine already answers mDNS for its hostname --- Avahi
on Linux, Bonjour on macOS and Windows do, out of the box --- the URL uses
that name instead of an address:

```
[*] https://your-pc.local:8443/Xk3...Qw/
[*] or https://192.168.35.9:8443/Xk3...Qw/   (certificate warning)
```

iOS resolves `.local` natively, so the phone needs nothing installed. The
name is only used when it already resolves to one of this machine's
addresses; a stale cache or a namesake on the LAN would otherwise send the
phone to a stranger's machine.

A name also survives a change of address, so the URL and the QR code stay
the same across reboots and new leases. The address URL is printed as a
fallback and is equally trusted --- both are in the certificate.

```
--name NAME   serve as NAME.local instead of the hostname
--no-mdns     ignore names, use addresses as before
```

Publishing a *different* name needs the optional dependency:

```sh
pip install -e ".[mdns]"      # brings in zeroconf
python -m filetransfer --name filedrop
```

mDNS rides on multicast, which guest Wi-Fi and client-isolated networks
block. That is what the address fallback is for.

The server listens on IPv4 and IPv6 on one socket, because a `.local` name
usually carries a link-local IPv6 record as well and iOS may try it first.

## Certificate

There are two certificates, the way `mkcert` does it:

| file | what it is | changes |
|---|---|---|
| `ca.pem` | the local authority. **This is the one the phone installs.** | ~never (10 years) |
| `cert.pem` | the server certificate, signed by the CA | whenever a name or address changes |

That split is the whole point. The phone trusts the authority, so the server
certificate underneath can be re-signed as often as it likes --- new Wi-Fi,
new DHCP lease, VPN up or down --- and the phone never has to be touched
again. Only a new `ca.pem` would mean another trip through Settings, and the
startup output says so explicitly when that happens.

### Trusting it on the iPhone, once

1. Open the URL. Safari warns, because nothing is trusted yet --- **Show
   Details** -> **visit this website**.
2. On the page, tap **Install the certificate**. That downloads `ca.pem`
   served as `application/x-x509-ca-cert`, which is what makes iOS offer to
   install it. Allow the profile.
3. Settings -> General -> **VPN & Device Management** -> install it.
4. Settings -> General -> About -> **Certificate Trust Settings** -> turn it
   on for "file-transfer local CA".

From then on there are no warnings, by name or by address, and it survives
restarts, new tokens and new addresses.

### Why the old single certificate was never trusted

A self-signed server certificate is not enough for iOS 13 and later, which
requires every TLS server certificate to carry an `extendedKeyUsage` of
`id-kp-serverAuth`. Without it the certificate is refused *even after* the
profile is installed and fully trusted, with no useful explanation. The leaf
now carries that EKU, a `keyUsage` of digital signature plus key
encipherment, the names in the `subjectAltName` (never the common name), and
a lifetime under Apple's 398-day limit.

To rebuild by hand, or to add a name:

```sh
python -m filetransfer.certs --force my-pc.local
```

`--force` replaces the authority too, so the phone will need steps 3 and 4
again. Leave it off to just re-sign the server certificate.

## Tests

```sh
python -m unittest discover -v
```

One test file per module: `test_addresses.py`, `test_certs.py`,
`test_server.py`, `test_cli.py`. The server tests start a real server on a
random port --- the upload folder and the token are constructor arguments,
so nothing has to be monkeypatched.

They also run on Linux and Windows via GitHub Actions (`.github/workflows/test.yml`).

## Notes

- Files are streamed to disk, so large files are fine.
- Filenames are reduced to their base name and stripped of characters Windows forbids; `../../etc/passwd` lands as `passwd` in `uploads/`.
- A name that already exists gets a suffix: `IMG_0001 (1).jpg`.
- Requests are handled in threads, so a stalled phone does not block others.
- Bound to `0.0.0.0:8443`. The token is the only protection (traffic is encrypted), so do not expose this to the internet.

### Firewall

- **Linux:** `sudo ufw allow 8443/tcp`
- **Windows:** allow `python.exe` on Private networks when prompted, or:

  ```powershell
  New-NetFirewallRule -DisplayName file-transfer -Direction Inbound `
    -Protocol TCP -LocalPort 8443 -Action Allow -Profile Private
  ```

## Troubleshooting

**`ModuleNotFoundError: multipart`** (or `filetransfer`)
Activate the venv and run `pip install -r requirements.txt`, from the project directory. Do **not** install `python-multipart`; it uses the same module name and conflicts.

**Cert warning keeps blocking upload**
Install **`ca.pem`**, not `cert.pem`, and enable it under Certificate Trust
Settings; see [Certificate](#certificate). Tapping **Install the
certificate** on the upload page is the easiest route. If you trusted a
certificate made by an older version of this tool, delete that profile ---
it lacked the `extendedKeyUsage` extension iOS requires and was never
actually trusted.

**Cannot reach the page**
Check the IP printed on startup, the firewall, and that both devices are on the same subnet. If the machine has several addresses, try the other `or ...` URLs, or pin the right one with `FILE_TRANSFER_HOST`. To reach the server *over* a VPN, pass its tunnel address that way --- it is skipped by default, and doing so rewrites the certificate. A VPN on the *iPhone* can also route the request away from the LAN --- turn it off there, or exclude the subnet.
