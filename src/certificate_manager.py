import requests
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from datetime import datetime, timezone

import logging


class CertificateManager:
    def __init__(self, api_key, ip_address, pem_private_key=None, pem_csr=None, 
                 cert_pem=None, ca_bundle_pem=None,  cert_list=None, key_data=None,
                 certificate_validity_days=90):
        
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self.API_BASE_URL = "https://api.zerossl.com"
        
        # Required variables (always needed)
        if not api_key or not ip_address:
            raise ValueError("api_key and ip_address must be provided.")
        self.api_key = api_key
        self.ip_address = ip_address
        
        # Certificate info
        self.certificate_id = None
        self.certificate_validity_days = certificate_validity_days
        self.cert_info_list = []
        self.cert_info = None
        
        # Validation
        self.validation_filename = None
        self.file_validation_content = None
        self.validation_url = None
        
        # Store the provided private key and CSR if available
        self.pem_private_key = pem_private_key
        self.pem_csr = pem_csr
        self.cert_pem = cert_pem
        self.ca_bundle_pem = ca_bundle_pem
        self.cert_list = cert_list
            
    @classmethod
    def from_csr(cls, api_key, ip_address, pem_private_key, pem_csr):
        """
        Initialize a CertificateManager instance using a private key and CSR.
        
        Args:
            api_key (str): API key for authentication.
            ip_address (str): IP address for the certificate.
            pem_private_key (str): The private key in PEM format.
            pem_csr (str): The CSR in PEM format.
            
        Returns:
            CertificateManager: The instance of the manager initialized with CSR data.
            
        Raises:
            ValueError: If pem_private_key or pem_csr is missing.
        """
        if not pem_private_key or not pem_csr:
            raise ValueError("pem_private_key and pem_csr must both be provided.")
        return cls(api_key=api_key, ip_address=ip_address, pem_private_key=pem_private_key, pem_csr=pem_csr)

    @classmethod
    def from_cert(cls, api_key, ip_address, cert_pem, pem_private_key, ca_bundle_pem=None):
        """
        Initialize a CertificateManager instance using a certificate, private key, and optionally a CA bundle.
        
        Args:
            api_key (str): API key for authentication.
            ip_address (str): IP address for the certificate.
            cert_pem (str): The certificate in PEM format.
            pem_private_key (str): The private key in PEM format.
            ca_bundle_pem (str, optional): The CA bundle in PEM format (default is None).
            
        Returns:
            CertificateManager: The instance of the manager initialized with certificate data.
            
        Raises:
            ValueError: If cert_pem or pem_private_key is missing.
        """
        if not cert_pem or not pem_private_key:
            raise ValueError("cert_pem, pem_private_key, must all be provided.")
        return cls(api_key=api_key, ip_address=ip_address, cert_pem=cert_pem, pem_private_key=pem_private_key, ca_bundle_pem=ca_bundle_pem)

    @classmethod
    def from_cert_list(cls, api_key, ip_address, cert_list, key_data):
        """
        Initialize a CertificateManager instance using a list of certificates and a private key.
        
        Args:
            api_key (str): API key for authentication.
            ip_address (str): IP address for the certificate.
            cert_list (list): A list of certificates (PEM format).
            key_data (str): The private key data in PEM format.
        
        Returns:
            CertificateManager: The instance of the manager initialized with cert list data.
            
        Raises:
            ValueError: If cert_list or key_data is missing.
        """
        if not cert_list or not key_data:
            raise ValueError("cert_list and key_data must both be provided.")
        
        instance = cls(api_key=api_key, ip_address=ip_address, cert_list=cert_list, key_data=key_data)
        cert_info_list = instance.__extract_certificates()
        
        if not cert_info_list:
            raise ValueError("No valid certificates found in the provided list.")
        
        instance.cert_pem = cert_list[0]
        instance.cert_info = cert_info_list[0]
        if len(cert_list) == 1:
            instance.logger.warning(f'Cert list contains only one certificate. CA bundle might be missing.')
        else:
            instance.ca_bundle_pem = cert_list[1]
            if len(cert_list) > 2:
                instance.logger.warning(f'Cert list contains more than two certificates. The first certificate will be the primary, the second will be the CA bundle, and the rest will be skipped.')

        instance.pem_private_key = key_data.encode('utf-8')
        
        return instance

    @classmethod
    def empty(cls, api_key, ip_address,key_size=2048):
        """
        Create an empty CertificateManager instance and generate CSR.
        
        Args:
            api_key (str): API key for authentication.
            ip_address (str): IP address for the certificate.
            key_size (int, optional): Cert key size (default is 2048).
            
        Returns:
            CertificateManager: The empty instance of the manager.
        """
        instance = cls(api_key=api_key, ip_address=ip_address)
        instance._generate_csr(key_size=key_size)
        return instance

    def _generate_csr(self, key_size=2048):
        # Generate a new private key and CSR
        self.logger.info(f"Generating private key with size: {key_size} bits..")
        
        try:
            # Generate a 2048-bit RSA key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )

            # Create a CSR
            self.logger.debug("Creating Certificate Signing Request (CSR).")
            csr = x509.CertificateSigningRequestBuilder().subject_name(
                x509.Name([
                    x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, self.ip_address)])
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Serialize private key and CSR to PEM format
            pem_private_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            pem_csr = csr.public_bytes(serialization.Encoding.PEM)

            # Store generated private key and CSR in the instance
            self.pem_private_key = pem_private_key
            self.pem_csr = pem_csr

            self.logger.info("Private key and CSR generated successfully.")
        
        except Exception as e:
            self.logger.error(f"Error generating CSR: {str(e)}")
            raise

    def validate_csr(self):
        """
        Validate the generated CSR using the ZeroSSL API.

        Returns:
            bool: True if the CSR is valid, False otherwise.
        
        Raises:
            Exception: If the CSR is not present in the instance.
        """
        if not self.pem_csr:
            self.logger.error("No CSR available to validate.")
            raise Exception("CSR is not available")

        url = f'{self.API_BASE_URL}/validation/csr?access_key={self.api_key}'
        payload = {'csr': self.pem_csr.decode('utf-8')}
        
        try:
            self.logger.debug(f'Validating CSR: {payload}')
            response = requests.post(url, json=payload)
            response.raise_for_status()
            result = response.json()
            self.logger.info(f'CSR validation result: {result}')
            
            if result.get('valid'):
                self.logger.info('CSR is valid.')
                return True
            else:
                self.logger.error(f"CSR validation failed: {result.get('error')}")
                return False
            
        except requests.exceptions.HTTPError as e:
            self.logger.error(f'Error validating CSR: {e.response.text}')
            return False
        except Exception as e:
            self.logger.error(f'Unexpected error during CSR validation: {str(e)}')
            return False


    def register_certificate(self):
        """
        Registers a new certificate with ZeroSSL using the current CSR.
        Validates the CSR, requests a certificate, and stores the certificate ID and validation info.
        
        Raises:
            Exception: If the CSR is invalid or certificate creation fails.
        """
        # Validate CSR
        if not self.validate_csr():
            self.logger.error("Invalid CSR. Aborting certificate request.")
            raise Exception("CSR validation failed")

        # API endpoint for creating certificates
        url = f'{self.API_BASE_URL}/certificates?access_key={self.api_key}'
        certificate_data = {
            "certificate_domains": self.ip_address,
            "certificate_validity_days": self.certificate_validity_days,
            "certificate_csr": self.pem_csr.decode('utf-8'),
            "strict_domains": 1
        }
        try:
            self.logger.info(f'Requesting certificate for IP: {self.ip_address}')
            self.logger.debug(f'Requesting URL: {url}')
            self.logger.debug(f'Request body: {certificate_data}')  # Log request body
        
            response = requests.post(url, json=certificate_data)
            response.raise_for_status()
            certificate_info = response.json()
            
            if not certificate_info.get('success', True):
                error_info = certificate_info.get('error', {})
                self.logger.error(f"Error issuing certificate: {error_info}")
                raise ValueError(f'Error issuing certificate')
            
            self.logger.debug(f'Response [{response.status_code}]: {response.text}')

            self.certificate_id = certificate_info['id']
            self.logger.info(f'Certificate successfully created, ID: {self.certificate_id}')
            
            validation_info = certificate_info.get('validation', {}).get('other_methods', {}).get(self.ip_address, {})
            
            if validation_info:
                self.file_validation_content = validation_info.get('file_validation_content')
                self.validation_url = validation_info.get('file_validation_url_http')
                self.validation_filename = urlparse(self.validation_url).path.split("/")[-1]
                self.logger.info(f'Validation content received: {self.file_validation_content}')
            else:
                raise ValueError('No validation info found.')
        except requests.exceptions.RequestException as e:
            self.logger.debug(f'Response [{response.status_code}]: {response.text}')
            self.logger.debug(f'Response body: {response.text}')
            self.logger.error(f'Error creating certificate: {str(e)}')
            raise
        
    def get_certificate(self):
        """
        Returns the certificate, CA bundle, and private key in PEM format.

        Returns:
            tuple: (cert_pem: str, ca_bundle_pem: str or None, private_key: str)
        """
        return  self.cert_pem, self.ca_bundle_pem, self.pem_private_key.decode('utf-8')

    def check_certificate_status(self):
        """
        Checks the current status of the certificate from ZeroSSL.

        Returns:
            str or None: Status of the certificate (e.g. 'draft', 'pending_validation', 'issued'), or None on error.
        """
        if not self.certificate_id:
            self.logger.error("Certificate ID not available.")
            return None
        
        url = f'{self.API_BASE_URL}/certificates/{self.certificate_id}?access_key={self.api_key}'
        self.logger.debug(f"Get status for certificate {self.certificate_id}")
        try:
            response = requests.get(url)
            response.raise_for_status()
            status_info = response.json()
            status = status_info.get('status')
            if not status:
                self.logger.warning(f'No "status" field in response: {status_info}')

            self.logger.info(f'Certificate status: {status}')
            return status
        except requests.exceptions.RequestException as e:
            self.logger.error(f'Error checking certificate status: {str(e)}')
            return None

    def verify_domains(self):
        """
        Triggers domain validation challenge for the certificate using ZeroSSL API.

        Returns:
            dict or None: API response containing validation status, or None if request fails.
        """
        if not self.certificate_id:
            self.logger.error("Certificate ID not available for domain verification.")
            return None
        
        url = f"{self.API_BASE_URL}/certificates/{self.certificate_id}/challenges?access_key={self.api_key}"
        # Parameters for verification
        params = {
            'validation_method': 'HTTP_CSR_HASH'
        }
        try:
            self.logger.debug(f"Sending POST request to: {url} with params: {params}")
            response = requests.post(url, params=params)

            # Check for successful response status
            response.raise_for_status()

            self.logger.debug(f"Received response: {response.text}")
            
            return response.json()
    
        except requests.exceptions.HTTPError as http_err:
            self.logger.error(f"HTTP error occurred: {http_err} - Status code: {response.status_code}")
        except requests.exceptions.ConnectionError as conn_err:
            self.logger.error(f"Connection error occurred: {conn_err}")
        except requests.exceptions.Timeout as timeout_err:
            self.logger.error(f"Timeout error occurred: {timeout_err}")
        except requests.exceptions.RequestException as req_err:
            self.logger.error(f"An error occurred: {req_err}")
        except ValueError as json_err:
            self.logger.error(f"JSON decode error: {json_err}")
        
        return None  
    
    def download_certificate(self):
        """
        Downloads the issued certificate and CA bundle from the ZeroSSL API.

        Returns:
            tuple(str, str) or None: A tuple of (certificate, CA bundle), or None if the request fails.
        """
        if not self.certificate_id:
            self.logger.error("Certificate ID is not available for download.")
            return None
        
        # Downloads the certificate and certificate bundle from ZeroSSL API
        url = f"{self.API_BASE_URL}/certificates/{self.certificate_id}/download/return?access_key={self.api_key}"
        
        params = {
            'include_cross_signed': 0
        }
        
        try:
            self.logger.info(f"Downloading certificate with ID: {self.certificate_id} from ZeroSSL.")
            response = requests.get(url, params=params)
            response.raise_for_status()  
            
            data = response.json()

            self.cert_pem = data.get('certificate.crt')
            self.ca_bundle_pem = data.get('ca_bundle.crt')
            
            if not self.cert_pem or not self.ca_bundle_pem:
                self.logger.error("Failed to retrieve certificate or CA bundle from the response.")
                return None

            self.logger.debug(f"Certificate got {self.cert_pem}.")
            self.logger.debug(f"CA Bundle got {self.ca_bundle_pem}.")
            
            return self.cert_pem, self.ca_bundle_pem
        
        except requests.exceptions.HTTPError as http_err:
            self.logger.error(f"HTTP error occurred while downloading certificate: {http_err}")
        except requests.exceptions.ConnectionError as conn_err:
            self.logger.error(f"Connection error occurred while downloading certificate: {conn_err}")
        except requests.exceptions.Timeout as timeout_err:
            self.logger.error(f"Timeout error occurred while downloading certificate: {timeout_err}")
        except requests.exceptions.RequestException as req_err:
            self.logger.error(f"Error occurred while downloading certificate: {req_err}")
        except ValueError as json_err:
            self.logger.error(f"JSON decode error occurred: {json_err}")
        
        return None

    def parse_cert(self, cert):
        """
        Parses a PEM-formatted certificate and extracts key information.

        Args:
            cert (str): Certificate in PEM format.

        Returns:
            dict or None: Dictionary with certificate information or None if parsing fails.
        """
        cert_info = {}
        try:
            # Load the certificate
            certificate = x509.load_pem_x509_certificate(cert.encode('utf-8'), default_backend())
            
            # Gather information about the certificate
            cert_info = {
                'subject': certificate.subject,
                'issuer': certificate.issuer,
                'not_valid_before': certificate.not_valid_before_utc,
                'not_valid_after': certificate.not_valid_after_utc,
                'serial_number': certificate.serial_number,
                'public_key': certificate.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8'),
                'san_ips': [],
                'san_dns': [],
            }
            # Try to extract SANs
            try:
                san_extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                self.logger.debug(f"SAN extension found for cert {cert_info['serial_number']}: {san_extension}")
                cert_info['san_ips'] = san_extension.value.get_values_for_type(x509.IPAddress)
                cert_info['san_dns'] = san_extension.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                self.logger.warning("No Subject Alternative Name extension found in the certificate.")
        
        except Exception as e:
            self.logger.error(f"Failed to load or parse a certificate: {e}")
            
        return cert_info
            
    def __extract_certificates(self):
        for cert in self.cert_list:
            self.cert_info_list.append(self.parse_cert(cert))
            self.logger.info(f"Successfully extracted information from a certificate.")
        if not self.cert_info_list:
            self.logger.warning("No valid certificates found in the provided list.")
        
        self.logger.debug(f"Extracted certificate info: {self.cert_info_list}")
            
        return self.cert_info_list
    
    def check_cert_key_match(self):
        """
        Check that the private key matches the public key in the certificate.

        The method compares the public key extracted from the private key with
        the public key in the certificate to ensure they match.

        Returns:
            bool: True if the public keys match, False otherwise.
        """
        # Check if cert_info exists, if not, parse the certificate
        if not self.cert_info:
            if not self.cert_pem:
                self.logger.error("Certificate not found.")
            self.cert_info = self.parse_cert(self.cert_pem)
        if not self.pem_private_key:
            self.logger.error("Private key not found.")
        try:
            # Load the private key
            private_key = serialization.load_pem_private_key(self.pem_private_key, password=None, backend=default_backend())

            # Get the public key from the private key
            public_key_from_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # Get the public key from the certificate
            public_key_from_cert = self.cert_info["public_key"]

            # Compare the two public keys
            return public_key_from_key == public_key_from_cert
        except Exception as e:
            print(f"Error checking certificate and key match: {e}")
            return False
        
    def is_certificate_expired(self):
        """
        Check if the certificate is expired or not.
        
        This method checks whether the certificate is valid based on its 'not_valid_before' 
        and 'not_valid_after' dates. It returns True if the certificate is expired, 
        False if it is still valid, and logs the appropriate messages.
        
        Returns:
            bool: True if the certificate is expired, False if it is still valid.
        """
        # Check if cert_info exists, if not, parse the certificate
        if not self.cert_info:
            if not self.cert_pem:
                self.logger.error("Certificate not found.")
            self.cert_info = self.parse_cert(self.cert_pem)
            
        # Get the current time in UTC
        current_time = datetime.now(timezone.utc)
        
        # Check if the certificate is expired
        if current_time < self.cert_info["not_valid_before"]:
            self.logger.warning(f"The certificate is not valid yet. Valid from {self.cert_info["not_valid_before"]}.")
            return False
        elif current_time > self.cert_info["not_valid_after"]:
            self.logger.debug(f"The certificate has expired. Expired on {self.cert_info["not_valid_after"]}.")
            return True
        else:
            self.logger.debug(f"The certificate is valid. It will expire on {self.cert_info["not_valid_after"]}.")
            return False

    def list_certificates(self, certificate_status=None, certificate_type=None, search=None, limit=100, page=1):
        """
        Lists certificates from the ZeroSSL API with optional filters.

        Args:
            certificate_status (str, optional): Filter by status.
            certificate_type (str, optional): Filter by type (e.g. 'single_domain').
            search (str, optional): Search term to filter certificates.
            limit (int, optional): Number of results per page.
            page (int, optional): Page number.

        Returns:
            dict or None: Parsed JSON response with certificate list or None on failure.
        """
        url = f"{self.API_BASE_URL}/certificates?access_key={self.api_key}"
        params = {
            "certificate_status": certificate_status,
            "certificate_type": certificate_type,
            "search": search,
            "limit": limit,
            "page": page
        }
        
        # Remove None values to avoid sending unnecessary parameters
        params = {k: v for k, v in params.items() if v is not None}
        self.logger.debug("Requesting certificates with parameters: %s", params)
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            self.logger.info("Successfully retrieved certificates from ZeroSSL API.")
            data = response.json()
            self.logger.debug(f"response: {data}")
            return data

        except requests.exceptions.HTTPError as http_err:
            self.logger.error(f"HTTP error occurred while listing certificates: {http_err}")
        except requests.exceptions.ConnectionError as conn_err:
            self.logger.error(f"Connection error occurred while listing certificates: {conn_err}")
        except requests.exceptions.Timeout as timeout_err:
            self.logger.error(f"Timeout error occurred while listing certificates: {timeout_err}")
        except requests.exceptions.RequestException as req_err:
            self.logger.error(f"Request error occurred while listing certificates: {req_err}")
        except ValueError as json_err:
            self.logger.error(f"JSON decode error occurred: {json_err}")
        
        return None
        
    def get_certs_by_san_ip(self):
        """
        Attempts to find and return metadata for the current certificate from the ZeroSSL API
        by matching the certificate's Subject Alternative Name (SAN) IP address and its validity period.

        The method:
            - Parses the current certificate if not already parsed.
            - Retrieves a list of certificates associated with the same IP address via ZeroSSL search.
            - Compares the validity period (not_valid_before and not_valid_after) of each result
            with the current certificate to find an exact match.

        Returns:
            dict: The matching certificate metadata from the ZeroSSL API if found.
            None: If no matching certificate is found, or an error occurs.

        Raises:
            Does not explicitly raise exceptions, but logs errors and gracefully returns None
            in case of issues (e.g., network errors, missing data).
        """
        # Check that cert_info exist
        if not self.cert_info:
            if not self.cert_pem:
                self.logger.error("Certificate not found.")
            self.cert_info = self.parse_cert(self.cert_pem)
            
        cert_list = self.list_certificates(search=self.ip_address)
        if not cert_list:
            self.logger.error(f"Certificates with ips {self.ip_address} not found")
            return None
        self.logger.debug(f'Current cert not_valid_before: {self.cert_info["not_valid_before"]} and not_valid_after: {self.cert_info["not_valid_after"]}')
        
        for cert in cert_list.get("results", []):
            # Parse validity dates from the certificate data
            created_date = datetime.strptime(cert["created"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            not_valid_after = datetime.strptime(cert["expires"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            not_valid_before = datetime(created_date.year, created_date.month, created_date.day, tzinfo=timezone.utc)
            if self.cert_info["not_valid_before"] ==  not_valid_before\
                and self.cert_info["not_valid_after"] == not_valid_after:
                return cert
            else:
                self.logger.debug(f'Cert id: {cert["id"]} has inappropriate time created {not_valid_before} and time expired {not_valid_after}')
        
        self.logger.error(f'Cert not found on zerossl.com')
        return None
    
    def get_cert_id(self):
        """
        Returns the certificate ID for the current certificate.

        If the `certificate_id` is not already set, this method attempts to retrieve
        it by querying the ZeroSSL API using the certificate's SAN IP and validity period.

        Returns:
            str: The certificate ID if found or already available.
            None: If the certificate ID could not be determined.
        """
        if not self.certificate_id:
            self.logger.warning(f"Certificate id is not set. Info about certificate will be requested from zerossl.com.")
            cert_info = self.get_certs_by_san_ip()
            if not cert_info:
                self.logger.error(f"Unable to find certificate information.")
                return None
            self.certificate_id = cert_info["id"]
            self.logger.info(f"Certificate ID retrieved: {self.certificate_id}")
        return self.certificate_id
    
    def get_certificate_validity_days(self):
        """
        Returns the number of days until the current certificate expires.

        This method ensures that the certificate has been loaded and parsed.
        It then calculates the difference between the expiration date of the certificate
        and the current UTC time, returning the number of remaining valid days.

        Returns:
            int: Days remaining before the certificate expires (returns 0 if already expired).
        """
        # Check that cert_info exist
        if not self.cert_info:
            if not self.cert_pem:
                self.logger.error("Certificate not found.")
            self.cert_info = self.parse_cert(self.cert_pem)
        not_valid_after = self.cert_info["not_valid_after"]
        
        today = datetime.now(not_valid_after.tzinfo)
        validity_days = (not_valid_after - today).days
        self.logger.debug(f"Days until expiration: {validity_days}")
        
        return max(validity_days, 0)

    def revoke_certificate(self, reason="unspecified"):
        """
        Revokes the current certificate using the ZeroSSL API.

        If the certificate information is not yet parsed, it attempts to parse it first.
        Sends a revocation request to the ZeroSSL API for the current `certificate_id`.

        Args:
            reason (str): Optional revocation reason (default: "unspecified").

        Returns:
            bool: True if the revocation was successful, False otherwise.
        """
        if not self.cert_info:
            if not self.cert_pem:
                self.logger.error("Certificate not found.")
                return False
            self.cert_info = self.parse_cert(self.cert_pem)
            
        if not self.certificate_id:
            self.logger.error("Cannot revoke certificate: certificate ID is not set.")
            return False            
        
        url = f"{self.API_BASE_URL}/certificates/{self.certificate_id}/revoke?access_key={self.api_key}"
        payload = {
            "reason": reason
        }
        
        try:
            self.logger.debug(f"Sending revocation request for certificate {self.certificate_id}. Payload: {payload}")
            response = requests.post(url, data=payload)

            try:
                response_data = response.json()
            except ValueError as json_err:
                self.logger.error(f"Failed to parse JSON response: {json_err}")
                return False
            
            # Check if revocation was successful
            if response_data.get("success") == 1:
                self.logger.info(f"Certificate {self.certificate_id} successfully revoked.")
                return True
            else:
                self.logger.error(f"Failed to revoke certificate {self.certificate_id}. Response: {response_data}")
                return False
        except requests.RequestException as e:
            self.logger.error(f"An error occurred while revoking the certificate {self.certificate_id}: {e}")
            return False
        
    def cancel_certificate(self):
        """
        Cancels the current certificate using the ZeroSSL API.

        Attempts to cancel the certificate identified by `certificate_id`. 
        If certificate info is not yet parsed, it parses it first.

        Returns:
            bool: True if cancellation succeeded, False otherwise.
        """
        if not self.cert_info:
            if not self.cert_pem:
                self.logger.error("Certificate not found.")
                return False
            self.cert_info = self.parse_cert(self.cert_pem)

        if not self.certificate_id:
            self.logger.error("Cannot cancel certificate: certificate ID is not set.")
            return False
            
        url = f"{self.API_BASE_URL}/certificates/{self.certificate_id}/cancel?access_key={self.api_key}"
        
        try:
            self.logger.debug(f"Sending cancel request for certificate {self.certificate_id}")
            response = requests.post(url)

            try:
                response_data = response.json()
            except ValueError as json_err:
                self.logger.error(f"Failed to parse JSON response: {json_err}")
                return False
            
            if response_data.get("success") == 1:
                self.logger.info(f"Certificate {self.certificate_id} successfully canceled.")
                return True
            else:
                self.logger.error(f"Failed to canceled certificate {self.certificate_id}. Response: {response_data}")
                return False
        except requests.RequestException as e:
            self.logger.error(f"An error occurred while revoking the certificate {self.certificate_id}: {e}")
            return False