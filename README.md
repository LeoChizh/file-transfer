# file-transfer

Tiny HTTPS file-drop server. Upload files from an iPhone (Safari) to a Linux or Windows machine over the LAN. No app, no cloud, no account.

## Layout

```
file-transfer/
  filetransfer/
    cli.py         argument parsing, the QR code, what gets printed
    mdns.py        the .local name, and checking it points here
    server.py      the HTTPS server and its one request handler
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

Everything it writes --- `ca.pem`, `ca-key.pem`, `cert.pem`, `key.pem`,
`token.txt`, `uploads/` --- lands in the current directory, so run it from
wherever you want the files. Leave it running; stop it with Ctrl-C.

```
--port PORT     port to listen on (default 8443)
--dir PATH      where files land (default ./uploads)
--name NAME     the name to serve under (default: this machine's .local name)
--no-publish    only use the name if something already answers for it
--cert PATH     --key PATH    --ca PATH    --ca-key PATH    --token-file PATH
```

It prints one URL, a QR code of it, and the secret token it contains:

```
[*] https://your-pc.local:8443/Xk3...Qw/
[*] first time on this phone? install https://your-pc.local:8443/Xk3...Qw/ca.pem
[*] saving into /home/user/file-transfer/uploads
```

### No addresses, by design

The URL is always a name, never an IP address. Addresses change --- new
Wi-Fi, a new DHCP lease, a VPN coming up --- and picking the right one out of
a machine's several is a guessing game that gets it wrong exactly when a VPN
is connected. A name does not have that problem: it is stable, it is what
goes in the certificate, and iOS resolves `.local` natively, so the phone
needs nothing installed to find it.

The tradeoff is real and worth knowing: **mDNS rides on multicast, and some
networks block it** --- guest Wi-Fi, client isolation, a few mesh routers. On
such a network there is no fallback and no way in. `localhost` and
`127.0.0.1` are always in the certificate, so the machine can always reach
itself, but that does not help the phone.

If the name does not resolve, the startup output says so rather than looking
like success:

```
[!] nothing answers for your-pc.local here, so the phone probably cannot
    reach it either: install the mdns extra to publish it, or pass --name
```

Avahi (Linux) and Bonjour (macOS, Windows) already answer for the machine's
own hostname, which is the usual case and needs nothing installed.
Publishing some *other* name needs the optional dependency:

```sh
pip install -e ".[mdns]"      # brings in zeroconf
python -m filetransfer --name filedrop
```

`--name` also takes a name from somewhere else entirely --- a static entry
on the router, say, or a hosts file --- in which case nothing has to be
published at all:

```sh
python -m filetransfer --name nas.lan --no-publish
```

A name is only used once it has been checked to resolve to *this* machine,
by asking the kernel to bind the address it resolves to. An address this
machine does not hold cannot be bound, so a namesake on the same LAN cannot
quietly capture the phone.

The server listens on IPv4 and IPv6 on one socket, because a `.local` name
usually carries a link-local IPv6 record as well and iOS may try it first.

## Upload from iPhone

1. Connect to the same Wi-Fi as the server.
2. In Safari, open the URL printed on startup, or scan the QR code.
3. First time only: warning → **Show Details** → **visit this website**, then
   **Install the certificate** on the page (see
   [Certificate](#certificate)). After that there are no warnings.
4. Pick one or more files → **Upload**. They appear in `uploads/`.

## Certificate

There are two certificates, the way `mkcert` does it:

| file | what it is | changes |
|---|---|---|
| `ca.pem` | the local authority. **This is the one the phone installs.** | ~never (10 years) |
| `cert.pem` | the server certificate, signed by the CA | whenever a name or address changes |

The authority is named after the machine and the day it was made, for
example `your-pc file-transfer CA 2026-10-26`. That is the only thing the
phone's Certificate Trust Settings shows, so it is what lets you tell one
machine's authority from another's --- or from an old one of your own that
is still sitting in the list. The name records when it was made, so it does
not change from one day to the next.

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

One test file per module: `test_mdns.py`, `test_certs.py`,
`test_server.py`, `test_cli.py`. The server tests start a real server on a
random port --- the upload folder and the token are constructor arguments,
so nothing has to be monkeypatched.

## Notes

- Files are streamed to disk, so large files are fine.
- Filenames are reduced to their base name and stripped of characters Windows forbids; `../../etc/passwd` lands as `passwd` in `uploads/`.
- A name that already exists gets a suffix: `IMG_0001 (1).jpg`.
- Requests are handled in threads, so a stalled phone does not block others.
- Bound to every interface on port 8443, IPv4 and IPv6. The token is the only protection (traffic is encrypted), so do not expose this to the internet.

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
First check the firewall and that both devices are on the same Wi-Fi. Then
check the name resolves from the phone at all: if the network blocks
multicast, `.local` will not work and there is no fallback --- see
[No addresses, by design](#no-addresses-by-design). A VPN on the *phone* can
also route the request away from the LAN; turn it off there. If the startup
output carried the `[!] nothing answers for ...` line, the name was already
known to be unusable. A VPN on the *iPhone* can also route the request away from the LAN --- turn it off there, or exclude the subnet.
