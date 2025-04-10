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
3 Certificate (< 500 bytes)
4 Certificate Verify (< 100 bytes)
5 server Finished (4 + hash.length = 36 bytes)
6 client Finished (4 + hash.length = 36 bytes)
      -- enough for client_application_traffic_secret_0

extra: server send new session tickets
```

Note: Use the transcript until "client Finished". No more. No less.


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
寫一個單獨的 test.py
根據 TLS 1.3 的 key schedule algorithm
使用 SHA256
input
- 沒有 PRK
- 使用 DH shared secret: sample_data/server_openssl_client/saved_server/003_dh_shared_secret
- 使用 transcript ./sample_data/server_openssl_client/saved_server/000_handshake_0  ./sample_data/server_openssl_client/saved_server/004_handshake_1
計算出 ./sample_data/server_openssl_client/saved_server/008_client_handshake_traffic_secret
可以使用 cryptomath.py
```

```
根據 TLS 1.3 的 key schedule algorithm
使用 SHA256
繼續 test.py
使用 ./sample_data/server_openssl_client/saved_server/ 中的 009_handshake_2 010_handshake_3 011_handshake_4 012_handshake_5 016_handshake_6 作為 transcript
計算出 ./sample_data/server_openssl_client/saved_server/014_client_application_traffic_secret_0
```