FILE-TRANSFER
=============

Tiny HTTPS file-drop server. Upload files from iPhone (Safari) to this
Linux box over LAN. No app, no cloud, no account.


LAYOUT
------

file-transfer/
  recv.py        the server
  cert.pem       self-signed cert (generate once)
  key.pem        cert key          (generate once)
  uploads/       files land here
  .venv/         python venv
  README.txt     this file


FIRST-TIME SETUP
----------------

cd ~/file-transfer

# venv + dependency
python3 -m venv .venv
source .venv/bin/activate
pip install multipart

# self-signed cert (once, valid 365 days)
./gen-cert.sh

RUN
---

cd ~/file-transfer
source .venv/bin/activate
python3 recv.py

Prints the URL, e.g.:

  [*] https://192.168.35.9:8443/
  [*] saving into /home/dmitry/file-transfer/uploads


UPLOAD FROM IPHONE
------------------

1. Same Wi-Fi as the Linux box.
2. Safari -> https://<linux-ip>:8443/   (use IP printed on startup)
3. Cert warning -> Show Details -> visit this website (once per device).
4. Pick a file -> Upload. It appears in uploads/ on the Linux box.


NOTES
-----

- Files are streamed to disk (f.save_as), so large files are fine.
- Filenames are sanitized with os.path.basename -- paths like
  ../../etc/passwd land as "passwd" inside uploads/.
- Server is single-threaded; one upload at a time. For concurrent
  use, swap HTTPServer for ThreadingHTTPServer in recv.py.
- Bound to 0.0.0.0:8443. LAN-only -- do not expose to the internet
  without adding auth.
- Firewall: sudo ufw allow 8443/tcp if the iPhone cannot connect.


TROUBLESHOOTING
---------------

- ModuleNotFoundError: multipart
    -> activate the venv, pip install multipart

- Cert warning keeps blocking upload
    -> install cert.pem on the iPhone once
       Settings -> General -> VPN & Device Management
       -> Certificate Trust Settings

- Cannot reach the page
    -> check hostname -I on Linux, firewall, and that both devices
       are on the same subnet
