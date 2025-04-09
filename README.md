This is a fork of tlslite-ng.

I only want to generate test vectors from it.

```
python3 -m venv tlslite-env
source tlslite-env/bin/activate
pip install ecdsa
PYTHONPATH=. ./scripts/tls.py
```

```
# for ecdsa_secp256r1_sha256
openssl req -x509 -nodes -days 365 -newkey ec:<(openssl ecparam -name prime256v1) -keyout server.key -out server.crt -sha256
```

grep "save_and_return()"

Saving data for key schedule debugging.
```
About to handshake...
Saving data to saved_server/handshake_0
Saving data to saved_server/dh_server_private_key
Saving data to saved_server/dh_client_public_key
Saving data to saved_server/dh_shared_secret
Saving data to saved_server/handshake_1
Saving data to saved_server/early_secret
Saving data to saved_server/handshake_secret
Saving data to saved_server/server_handshake_traffic_secret
Saving data to saved_server/client_handshake_traffic_secret
Saving data to saved_server/handshake_2
Saving data to saved_server/handshake_3
Saving data to saved_server/handshake_4
Saving data to saved_server/handshake_5
Saving data to saved_server/master_secret
Saving data to saved_server/client_application_traffic_secret_0
Saving data to saved_server/server_application_traffic_secret_0
Saving data to saved_server/handshake_6
Saving data to saved_server/handshake_7
Saving data to saved_server/handshake_8
  Handshake time: 0.077 seconds
  Version: TLS 1.3
```  