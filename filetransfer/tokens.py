"""The shared secret that every URL carries.

A fresh one on every start, so an old bookmark or a screenshot of the QR
code stops working once the server is restarted.
"""
import secrets


def new_token():
    return secrets.token_urlsafe(16)
