This repo is forked from tlslight-ng.

Its purpose is to generate test vectors for developing other TLS implementations. (see sample_data/)

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
./openssl_client.sh
```

```
rm -fR saved_server/; ./server.sh

# with SSLKEYLOGFILE
rm -fR saved_client/; ./tcpdump.sh ./openssl_client.sh  
```

(TODO: ./client.sh might have some problem)



Usually there will be those handshake messages:
```
0 Client Hello
      -- enough for client_early_traffic_secret
1 Server Hello
      -- enough for client_handshake_traffic_secret
2 Encrypted Extensions (very small)
3 Certificate
4 Certificate Verify
5 server Finished (4 + (256 or 384)/8 = 36 or 52 bytes)
      -- enough for client_application_traffic_secret_0

6 client Finished (4 + (256 or 384)/8 = 36 or 52 bytes)

extra: server send new session tickets
```

Note: Use the transcript until "server Finished". No more. No less.


```
% find . | grep saved | grep 'handshake_[0-9]' | sort | xargs -n 1 python3 ./identify_handshake.py
./sample_data/server_openssl_client/saved_server/000_handshake_0: client_hello (1)
./sample_data/server_openssl_client/saved_server/004_handshake_1: server_hello (2)
./sample_data/server_openssl_client/saved_server/009_handshake_2: encrypted_extensions (8)
./sample_data/server_openssl_client/saved_server/010_handshake_3: certificate (11)
./sample_data/server_openssl_client/saved_server/011_handshake_4: certificate_verify (15)
./sample_data/server_openssl_client/saved_server/012_handshake_5: finished (20)
./sample_data/server_openssl_client/saved_server/016_handshake_6: finished (20)
./sample_data/server_openssl_client/saved_server/017_handshake_7: new_session_ticket (4)
./sample_data/server_openssl_client/saved_server/018_handshake_8: new_session_ticket (4)
```

```
% python3 key_schedule.py
early_secret:  33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
handshake_secret:  3d396f96859bf31eee1975b26b3b378ef14169a854b952233aca407c42652a2f
client_handshake_traffic_secret:  d615407856d6a7b5bc459ed54fa575cb59a33e82feda74999f194b7a23e77b92
server_handshake_traffic_secret:  5845a283de787073803f744b19d3de6c46962e0bd60e38e3c7fee805edfb84fa
master_secret:  4bbc3ae2215f3b366f3b233a6beaf3fa006d716c9d30b0b546203bda5ff02a6a
client_application_traffic_secret_0:  9e02432be8b4d2786c8b5686f1fb4c5f9de9071212425ff089136369f1a0c97a
server_application_traffic_secret_0:  22f1d85fee065f6761b9ecb1bbee4e7751a45dbebf67f7ba45f6b035818aa089
compare with keylog.txt:
SERVER_TRAFFIC_SECRET_0 95310ebc20ca48ea1a1050ce1c3792fc7b63cf84eaaa3ac3559f0b727ee32280 22f1d85fee065f6761b9ecb1bbee4e7751a45dbebf67f7ba45f6b035818aa089
```