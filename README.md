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
