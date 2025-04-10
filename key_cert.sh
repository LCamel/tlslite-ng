#!/bin/bash
# for ecdsa_secp256r1_sha256
openssl req -x509 -nodes -days 365 -newkey ec:<(openssl ecparam -name prime256v1) -keyout server.key -out server.crt -sha256
