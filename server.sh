#!/bin/sh
PYTHONPATH=. ./scripts/tls.py server -c server.crt -k server.key 127.0.0.1:4433
