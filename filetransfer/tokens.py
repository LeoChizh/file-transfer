"""The shared secret that every URL carries.

A fresh one on every start, so an old bookmark or a screenshot of the QR
code stops working once the server is restarted.
"""
import secrets

TOKEN_FILE = "token.txt"


def new_token():
    return secrets.token_urlsafe(16)


def write_token(path, token):
    """Save the token so it can be looked up without scrolling the terminal."""
    with open(path, "w") as fh:
        fh.write(token + "\n")
