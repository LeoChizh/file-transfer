#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
if [[ -f cert.pem && -f key.pem ]]; then
  echo "cert.pem / key.pem already exist, refusing to overwrite"
  exit 0
fi
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem \
  -days 365 -subj "/CN=filetransfer"
echo "generated cert.pem / key.pem"
