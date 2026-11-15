# Matrix Redaction Logger

Logs redactions in a given set of matrix rooms

## howto

1. `git clone https://github.com/thies23/matrix-redaction-logger`
2. `python3 -m venv .venv`
3. `source .venv/bin/activate`
4. `pip3 install -r requirements.txt`
5. `cp config.example.ini config.ini`
6. Edit `config.ini`
7. `python3 matrix_redaction_logger.py`
8. `python3 redaction_viewer.py`
9. ...
10. Profit!

On first run `redaction_viewer.py` downloads a bootstrap css from the given URL to serve it locally.

**Both Tools need to be run from the same folder and venv.**

## AUTH

**There is no auth!**

This tool saves all redacted messages. **PLEASE** protect it, with something like a htbasicauth or don't expose it to the internet at all!

This tool also allows you to join or leave any channel with the bot. So **please** *really* **PROTECT THE INTERFACE**