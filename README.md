# file-transfer

Tiny HTTPS file-drop server. Upload files from an iPhone (Safari) to a Linux or Windows machine over the LAN. No app, no cloud, no account.

## Layout

```
file-transfer/
  filetransfer/
    cli.py         argument parsing, the QR code, what gets printed
    server.py      the HTTPS server and its one request handler
    addresses.py   which address of this machine to advertise
    certs.py       makes cert.pem / key.pem (cross-platform)
    names.py       safe, non-colliding names for uploaded files
    page.py        the upload form and file listing
    tokens.py      the shared secret in every URL
  pyproject.toml   installable, provides the `file-transfer` command
  cert.pem         self-signed cert (created automatically)
  key.pem          cert key (created automatically)
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

## Certificate

The server creates the certificate automatically if it is missing, so making one by hand is optional.

It is **not** regenerated on every start: iOS trusts one specific certificate, so that would force a reinstall on the phone each time. A new one is made only when the cert is missing, expires within 30 days, or no longer covers one of this machine's LAN addresses. Connecting or dropping a VPN does **not** count: tunnel addresses are deliberately left out, so the certificate on the phone keeps working either way. A warning is printed when a new one is made.

Every served address goes into the certificate's `subjectAltName`, which iOS requires. To add a hostname or force a new cert:

```sh
python -m filetransfer.certs --force my-pc.local
```

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
Install `cert.pem` on the iPhone once (AirDrop or email it, then open it):
Settings → General → VPN & Device Management → install, then
Settings → General → About → Certificate Trust Settings → enable full trust.

**Cannot reach the page**
Check the IP printed on startup, the firewall, and that both devices are on the same subnet. If the machine has several addresses, try the other `or ...` URLs, or pin the right one with `FILE_TRANSFER_HOST`. To reach the server *over* a VPN, pass its tunnel address that way --- it is skipped by default, and doing so rewrites the certificate. A VPN on the *iPhone* can also route the request away from the LAN --- turn it off there, or exclude the subnet.
