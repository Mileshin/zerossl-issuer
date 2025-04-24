from kubernetes import client, config
import logging


class KubernetesClient:
    def __init__(self):
        """
        Initialize the Kubernetes client for interaction with the cluster.
        Tries to load the in-cluster configuration, and if it fails,
        it loads the kubeconfig from the local system.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        
        try:
            # This only works in k8s pods
            config.load_incluster_config()
            self.logger.info("Loaded in-cluster Kubernetes configuration.")
        except config.ConfigException:
            self.logger.warning("In-cluster configuration failed. Loading local kubeconfig...")
            try:
                config.load_kube_config()
                self.logger.info("Loaded local Kubernetes configuration.")
            except config.ConfigException as e:
                self.logger.error(f"Failed to load Kubernetes configuration: {e}")
                raise RuntimeError("Failed to load Kubernetes configuration. Please check the kubeconfig.") from e
        

        # Initialize the CoreV1Api client
        try:
            self.v1 = client.CoreV1Api()
            self.logger.info("Initialized Kubernetes CoreV1Api client.")
        except Exception as e:
            self.logger.error(f"Failed to initialize Kubernetes API client: {e}")
            raise RuntimeError("Failed to initialize Kubernetes API client.") from e

        

    def _get_external_ip(self, node, ip_version='ipv4'):
        """
        Helper function to get the external IP of a node based on IP version.

        Args:
            node: The Kubernetes node object.
            ip_version (str): The IP version to check ('ipv4' or 'ipv6').

        Returns:
            str or None: The external IP address if found, otherwise None.
        """
        if not hasattr(node, 'status') or not hasattr(node.status, 'addresses'):
            self.logger.error(f"Node {node.metadata.name} does not have status or addresses.")
            return None
        for address in node.status.addresses:
            if address.type == 'ExternalIP':
                if ip_version == 'ipv4' and '.' in address.address:
                    return address.address
                elif ip_version == 'ipv6' and ':' in address.address:
                    return address.address
        self.logger.warning(f"No external {ip_version} IP found for node {node.metadata.name}.")
        return None


        
    def get_node_external_ip(self, node_name=None, ip_version='ipv4'):
        """
        Get the external IP of a specific node or all nodes in the cluster.

        Args:
            node_name (str): The name of the node to query. If None, fetches for all nodes.
            ip_version (str): The IP version to filter by ('ipv4' or 'ipv6').

        Returns:
            dict or list: A dictionary with node name and external IP, or a list of nodes with external IPs.
        """
        try:                
            if node_name:
                node = self.v1.read_node(name=node_name)
                external_ip = self._get_external_ip(node, ip_version)
                        
                if not external_ip:
                    self.logger.warning(f"External IP not found for node: {node_name}")
                    return None
                
                return {"node_name": node_name, "external_ip": external_ip}
            else:
                nodes = self.v1.list_node()
                if not nodes.items:
                    self.logger.warning("No nodes found in the cluster.")
                    return None
                node_ips = [
                            {
                                "node_name": node.metadata.name,
                                "external_ip": self._get_external_ip(node, ip_version)
                            }
                            for node in nodes.items if self._get_external_ip(node, ip_version)
                        ]
                if not node_ips:
                    self.logger.warning("No external IPs found for nodes")
                    return None
                return node_ips
        except client.exceptions.ApiException as e:
            self.logger.error(f"Kubernetes API exception: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            return None