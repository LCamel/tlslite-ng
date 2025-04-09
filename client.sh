#!/bin/sh
PYTHONPATH=. ./scripts/tls.py client --cipherlist aes128gcm  --max-ver tls1.3 localhost:4433
