import os
import sys
import time
import threading
from flask import Flask, jsonify
from certificate_manager import CertificateManager
from kube_info import KubernetesClient
import logging
import requests

app = Flask(__name__)
new_manager = None

# Set up logging
def configure_logging(main_log_level, flask_log_level, cert_manager_log_level):
    # main logger
    logging.basicConfig(
        level=main_log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Flask log level
    flask_logger = app.logger
    flask_logger.setLevel(flask_log_level)

    # certificate manager log level
    cert_manager_logger = logging.getLogger('CertificateManager')
    cert_manager_logger.setLevel(cert_manager_log_level)
    
    # kube_info log manager the same level that for main
    kube_info_logger = logging.getLogger('KubernetesClient')
    kube_info_logger.setLevel(main_log_level)

## flask server
def run_app():
    # Run the Flask application.
    app.run(host='0.0.0.0', port=80)

@app.route('/.well-known/pki-validation/<filename>', methods=['GET'])
def verify_challenge(filename):
    # Handle validation challenge.
    global new_manager
    app.logger.info(f'Challenge received for file: {filename}')
    #  Our certificate is registered after getting request 

    if filename == new_manager.validation_filename:
        app.logger.debug(f'Return file_validation_content: {new_manager.file_validation_content}')
        return "\n".join(list(new_manager.file_validation_content)), 200
    else:
        app.logger.warning('Received invalid filename.')
        return jsonify({'status': 'verification failed'}), 404

def verify_cert(interval=60,repeat=300):
    """
    Periodically checks the certificate status until it is either issued or failed.

    This function runs a loop that queries the certificate status from `new_manager`
    every `interval` seconds. If the status is 'issued' or 'failed', the loop stops.

    Args:
        interval (int): Time in seconds between status checks. Defaults to 60.
    """
    global new_manager
    
    retry_delay = 0
    while True:
        if retry_delay <= 0:
            # Start certifficate challange
            if not new_manager.verify_domains():
                raise ValueError("Check failed")
            retry_delay = repeat
        status = new_manager.check_certificate_status()
        if status == 'issued':
            logging.info("Certificate has been issued. Stopping Flask server.")
            break
        elif status == 'failed':
            logging.error("Certificate validation failed. Stopping Flask server.")
            break
        else:
            logging.info(f"Certificate status is '{status}'. Will check again in {interval} seconds.")
            time.sleep(interval)
        retry_delay -= interval

def save_cert_and_key(cert_pem, ca_bundle_pem, key_pem, cert_file_path, key_file_path):
    """
    Save the certificate, CA bundle, and private key to their respective file paths.

    Args:
        cert_pem (str): The certificate in PEM format.
        ca_bundle_pem (str): The CA bundle in PEM format.
        key_pem (str): The private key in PEM format.
        cert_file_path (str): Path where the certificate will be saved.
        key_file_path (str): Path where the private key will be saved.

    Raises:
        IOError: If writing to the file system fails.
    """
    try:
        with open(cert_file_path, 'w') as cert_file:
            cert_file.write(cert_pem.strip() + "\n")
            cert_file.write(ca_bundle_pem.strip() + "\n")
        logging.info(f"Certificate saved to {cert_file_path}")
        
        with open(key_file_path, 'w') as key_file:
            key_file.write(key_pem.strip() + "\n")
        os.chmod(key_file_path, 0o600)
        logging.info(f"Private key saved to {key_file_path}")

    except Exception as e:
        logging.error(f"Error saving cert or key: {e}")
        raise

def split_certificates(cert_data):
    """
    Split a PEM-formatted certificate bundle into a list of individual certificates.

    Args:
        cert_data (str): A string containing one or more concatenated certificates in PEM format.

    Returns:
        list of str: A list of individual PEM certificates as strings.
    """
    certs = cert_data.split('-----END CERTIFICATE-----')

    # Store valid certificates
    cert_list = []

    for cert in certs:
        # Check that the segment contains a certificate
        if '-----BEGIN CERTIFICATE-----' in cert:
            cert = cert.strip() + '-----END CERTIFICATE-----'  # Re-add the END line
            cert_list.append(cert)

    if not cert_list:
        logging.warning("No valid certificates found after splitting.")
        
    return cert_list

def read_certificates(cert_file_path):
    """
    Read a PEM-formatted certificate bundle from a file and return individual certificates.

    Args:
        cert_file_path (str): Path to the PEM certificate file.

    Returns:
        list of str or None: List of individual PEM certificates as strings, or None if not found or invalid.
    """
    if not os.path.exists(cert_file_path):
        logging.warning(f'Certificate {cert_file_path} not found.')
        return None
    
    logging.info(f'Certificate {cert_file_path} already exist.')
    
    try:          
        # Read cert_file_path content
        with open(cert_file_path, "r") as file:
            certificate_data = file.read()
            logging.info(f"Successfully read file: {cert_file_path}")
            logging.debug(f"File {cert_file_path} contains: {certificate_data}")
    except Exception as e:
        # Log the error with exception details
        logging.error(f"Error reading file {cert_file_path}: {e}")
        sys.exit(1)
        
    cert_list = split_certificates(certificate_data)   

    if not(cert_list):
        logging.warning(f'File {cert_file_path} does not contain any certificates.')
        return None
    return cert_list

def read_key(key_file_path):
    """
    Reads and validates a private key file (either RSA or generic).

    Args:
        key_file_path (str): Path to the private key file.

    Returns:
        str or None: The key content if valid, otherwise None.
    """
    if not os.path.exists(key_file_path):
        logging.warning(f'Key file not found: {key_file_path}')
        return None

    logging.info(f'Key file exists: {key_file_path}')

    try:
        with open(key_file_path, "r") as file:
            key_data = file.read()
            logging.info(f"Successfully read key file: {key_file_path}")
            logging.debug(f"Key file contents: {key_data}")
    except Exception as e:
        logging.error(f"Error reading key file {key_file_path}: {e}")
        sys.exit(1)

    # Markers for RSA and generic private keys
    formats = [
        ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
        ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
    ]

    for begin, end in formats:
        if begin in key_data and end in key_data:
            if key_data.index(begin) < key_data.index(end):
                logging.info(f"Private key is properly structured: {begin.split()[1]}")
                return key_data
            else:
                logging.warning(f"Invalid key structure in file: 'BEGIN' appears after 'END' for format: {begin}")
                return None

    logging.warning("The file does not contain a complete private key.")
    return None
    
def generate_new_cert(api_key, ip_address):
    """
    Generates a new certificate by interacting with the CertificateManager.
    
    Args:
        api_key (str): API key for certificate registration.
        ip_address (str): IP address for certificate validation.
        cert_file_path (str): Path to save the certificate PEM file.
        key_file_path (str): Path to save the private key PEM file.
    
    Raises:
        ValueError: If any validation or registration step fails.
    """
    global new_manager
   # Initialize the certificate manager with preloaded key/CSR if available
    new_manager = CertificateManager.empty(api_key, ip_address)
    
    # Validate cert
    if not new_manager.validate_csr():
        raise ValueError("Certificate invalid")
    
    # Register certifficate
    new_manager.register_certificate()

    # Listen endpoint for checking
    app_thread = threading.Thread(target=run_app)
    app_thread.daemon = True ## This thread finish with main
    app_thread.start()

    # Wait before check
    time.sleep(5)
    
    verify_cert(60)
    
    new_manager.download_certificate()
    
    cert_pem, ca_bundle_pem, key_pem = new_manager.get_certificate()
    
    logging.debug(f'Generated key: {key_pem}')
    logging.debug(f'Generated cert: {cert_pem}')
    logging.debug(f'Generated ca_bundle: {cert_pem}')
    
    save_cert_and_key(cert_pem, ca_bundle_pem, key_pem, cert_file_path, key_file_path)

if __name__ == '__main__':
    # Get variables from environment
    api_key = os.getenv('ZEROSSL_API_KEY')
    ip_address = os.getenv('EXTERNAL_IP')
    node_name = os.getenv('NODE_NAME')
    cert_file_path = os.getenv('CERT_FILE_PATH', '/certs/tls.crt')
    key_file_path = os.getenv('KEY_FILE_PATH', '/certs/tls.key')
    main_log_level = getattr(logging, os.environ.get('LOG_LEVEL', 'WARNING').upper())
    flask_log_level = os.getenv('FLASK_LOG_LEVEL', main_log_level)
    cert_manager_log_level = os.getenv('CERT_MANAGER_LOG_LEVEL', main_log_level)
    renewal_threshold_days = int(os.getenv('RENEWAL_THRESHOLD_DAYS', 14))
    
    # Configure logging
    configure_logging(main_log_level, flask_log_level, cert_manager_log_level)

    # Validate input
    if not api_key:
        logging.error('Please set ZEROSSL_API_KEY environment variables.')
        sys.exit(1)
    if not node_name and not ip_address:
        logging.error('Please set EXTERNAL_IP or NODE_NAME environment variables.')
        sys.exit(1)
    if node_name and ip_address:
        logging.error('Both variables were set to EXTERNAL_IP NODE_NAME. Please select only one.')
        sys.exit(1)
        

    if node_name:
        # Kubernetes client to fetch external IP if node_name is set
        kube_info = KubernetesClient()
        node_info = kube_info.get_node_external_ip(node_name,'ipv4')
        if not node_info:
            logging.warning(f"External IP not found for node: {node_name}")
        else:
            ip_address = node_info["external_ip"]
            
    # Read certificates and key
    cert_list   = read_certificates(cert_file_path)
    key_data    = read_key(key_file_path)
    
    if cert_list and key_data:
        manager = CertificateManager.from_cert_list(api_key=api_key,ip_address=ip_address,
                                      cert_list=cert_list,key_data=key_data)
        # Check if public key and private key match
        if not manager.check_cert_key_match():
            logging.warning("Public key and private key don't match. New cert will be cerated.")
            generate_new_cert(api_key, ip_address)
        else:
            logging.info("Public key and private key matched")
            if manager.is_certificate_expired():    
                logging.warning("The certificate has expired. New cert will be created.")
                generate_new_cert(api_key, ip_address)
            else:
                logging.info("The certificate is valid.")
                # We should undrestand exist or not this cert on zerossl side
                if not manager.get_cert_id():
                    logging.error("This cert not found on zerossl side")
                    sys.exit(1)

                get_certificate_validity_days = manager.get_certificate_validity_days()
                if renewal_threshold_days > get_certificate_validity_days:
                    logging.info(f"The certificate expires in {get_certificate_validity_days}. It will be reissued")
                    generate_new_cert(api_key, ip_address) 

    else:
        logging.info("Cert or key not found. New cert will be created.")
        generate_new_cert(api_key, ip_address)
    
 