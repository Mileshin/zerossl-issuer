# zerossl-issuer
A simple utility that issues SSL certificates for IP addresses using the ZeroSSL API.

**zerossl-issuer** is a Python-based utility designed to manage the lifecycle of SSL/TLS certificates. It automates:

- Certificate Generation  
- Validation and Parsing  
- Renewal and Deployment  

The tool integrates with the external API of [ZeroSSL](https://zerossl.com) for certificate issuance, validates certificate integrity, and ensures smooth deployment to web servers or other components.

---

## Key Use Cases

- Automating SSL/TLS certificate renewal  
- Verifying certificate validity and expiration  
- Seamless deployment of new certificates  

---

## Environment Variables

| Variable | Description |
|---------|-------------|
| `ZEROSSL_API_KEY` | Required. API key for authenticating with the ZeroSSL API. |
| `EXTERNAL_IP` | Required if `NODE_NAME` is not set. The external IP address associated with the certificate. Incompatible with `NODE_NAME`. |
| `NODE_NAME` | Required if `EXTERNAL_IP` is not set. Name of the Kubernetes node. Used to retrieve the external IP from Node. |
| `CERT_FILE_PATH` | Optional. Path to the TLS certificate file. Defaults to `/certs/tls.crt`. |
| `KEY_FILE_PATH` | Optional. Path to the private key file. Defaults to `/certs/tls.key`. |
| `LOG_LEVEL` | Optional. Logging level for the main application. Options: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Defaults to `WARNING`. |
| `FLASK_LOG_LEVEL` | Optional. Logging level for the Flask app. Inherits from `LOG_LEVEL` if not specified. |
| `CERT_MANAGER_LOG_LEVEL` | Optional. Logging level for the certificate manager. Inherits from `LOG_LEVEL` if not specified. |
| `RENEWAL_THRESHOLD_DAYS` | Optional. Days before expiration to start renewal. Defaults to `14`. |

---

## Logs

To improve clarity and reduce noise in debug mode, separate loggers are used for:

- The main application  
- The Flask application  
- The certificate manager  

Log levels are configurable independently via environment variables.

---

## Workflow

### Certificate Checking

1. **Read Environment Variables**  
   Load required configuration for the application.

2. **Node and IP Handling**  
   If `NODE_NAME` is set but `EXTERNAL_IP` is not, retrieve the external IP from `kube-info`.

3. **Certificate and Key Reading**  
   Attempt to read the certificate and key files. If invalid or missing, trigger certificate creation.

4. **Initialize Certificate Manager**  
   Set up the certificate manager with the current certificate and key.

5. **Certificate Validity Check**  
   - Validate key matches the certificate  
   - Check certificate expiration  
   If any check fails, a new certificate is created.

6. **ZeroSSL Server Validation**  
   Ensure the certificate exists on the ZeroSSL server. Exit with code `1` if not found.

7. **Certificate Life Span Check**  
   If the remaining validity is below the threshold (`RENEWAL_THRESHOLD_DAYS`), renew the certificate.

---

### Certificate Creation Workflow

1. **Create New Certificate**  
   Initialize a new certificate manager and register a CSR with ZeroSSL.

2. **Flask App Setup**  
   Launch a Flask application in a background thread to support domain/IP verification.

3. **Domain (IP) Verification**  
   Start domain verification with ZeroSSL in the main thread.

4. **Monitor Certificate Status**  
   Periodically (every minute) check the verification status until completion.

5. **Download Verified Certificate**  
   Once verified, download the certificate from ZeroSSL.

6. **Save Certificate and Key**  
   Save the certificate and key to the specified file paths on the node.

---

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