# file-transfer

Tiny HTTPS file-drop server. Upload files from an iPhone (Safari) to a Linux or Windows machine over the LAN. No app, no cloud, no account.

## Layout

```
file-transfer/
  recv.py        the server
  gen_cert.py    makes cert.pem / key.pem (cross-platform)
  cert.pem       self-signed cert (created automatically)
  key.pem        cert key (created automatically)
  token.txt      current secret used in the URL (rewritten on every start)
  uploads/       files land here
  tests/         unit tests
  .venv/         python venv
```

## Setup

**Linux / macOS**

```sh
cd ~/file-transfer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell)**

```powershell
cd file-transfer
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run

```sh
python recv.py        # python3 on Linux
```

It prints the URL, including the secret token:

```
[*] https://192.168.35.9:8443/Xk3...Qw/
[*] saving into /home/user/file-transfer/uploads
```

A QR code of the URL is drawn above it: scan it with the iPhone camera instead of typing the token. (Needs the `qrcode` package; without it only the URL is printed.)

Open exactly that URL. Anything without the token returns 404, for uploads and downloads alike. The token is regenerated on every start, so old URLs and bookmarks stop working after a restart; scan the new QR code. `token.txt` just holds the current one.

## Upload from iPhone

1. Connect to the same Wi-Fi as the server.
2. In Safari, open the URL printed on startup.
3. Cert warning: **Show Details** → **visit this website** (once per device).
4. Pick one or more files → **Upload**. They appear in `uploads/`.

## Certificate

`recv.py` creates the certificate automatically if it is missing, so running `gen_cert.py` by hand is optional.

It is **not** regenerated on every start: iOS trusts one specific certificate, so that would force a reinstall on the phone each time. A new one is made only when the cert is missing, expires within 30 days, or no longer contains this machine's LAN IP. A warning is printed when that happens.

The LAN IP goes into the certificate's `subjectAltName`, which iOS requires. To add a hostname or force a new cert:

```sh
python gen_cert.py --force my-pc.local
```

## Tests

```sh
python -m unittest discover -v
```

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

**`ModuleNotFoundError: multipart`**
Activate the venv and run `pip install -r requirements.txt`. Do **not** install `python-multipart`; it uses the same module name and conflicts.

**Cert warning keeps blocking upload**
Install `cert.pem` on the iPhone once (AirDrop or email it, then open it):
Settings → General → VPN & Device Management → install, then
Settings → General → About → Certificate Trust Settings → enable full trust.

**Cannot reach the page**
Check the IP printed on startup, the firewall, and that both devices are on the same subnet.
