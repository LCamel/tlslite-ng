This repo is forked from tlslight-ng.

Its purpose is to generate test vectors for developing other TLS implementations.

Main changes:
- Added lots of `debug_save()` calls.
- Added some handy scripts in the root directory.
- When running, it generates `saved_server/` and `saved_client/`, which are the main outputs.

```
python3 -m venv tlslite-env
source tlslite-env/bin/activate
pip install ecdsa
./key_cert.sh

./server.sh

# in another shell
./client.sh
./test_tls13_minimal.sh
```


There shall be outputs like:
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