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
./client.sh
or
./openssl_client.sh
```

```
rm -fR saved_server/; ./server.sh

# without SSLKEYLOGFILE
rm -fR saved_client/; ./tcpdump.sh ./client.sh
# with SSLKEYLOGFILE
rm -fR saved_client/; ./tcpdump.sh ./openssl_client.sh  
```



There shall be outputs like:


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

extra: server send tickets
```

Note: Use the transcript until "client Finished". No more. No less.
