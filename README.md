# zerossl-issuer
A simple utility that issues SSL certificates for IP addresses using the ZeroSSL API.

## Local checking
Build:
```sh
docker build -t zerossl-issuer .
```
Run:
```sh
docker run -d \
    --name zerossl-issuer \
    -e ZEROSSL_API_KEY=<token> \
    -e EXTERNAL_IP=<ip> \
    -e CERT_FILE_PATH=/tmp/certificate.crt \
    -e KEY_FILE_PATH=/tmp/private.key \
    -e LOG_LEVEL="DEBUG" \
    -p 80:80 \
    zerossl-issuer
```
