import logging
from kubernetes import client
from kubernetes.client.exceptions import ApiException
from src.KubernetesAPI import KubernetesAPI
import re


class Domain:
    def __init__(self, name, namespace):
        """
        Initialize the Domains instance with namespace and resource name.

        Args:
            name (str): Resource name
            namespace (str): Kubernetes namespace
        """
        self.name = name
        self.namespace = namespace

    def validate_domain(self, domain):
        """
        Validate domain configuration with more comprehensive checks.

        Args:
            domain (dict): Domain configuration dictionary

        Raises:
            ValueError: If domain configuration is invalid
        """
        if not domain or not isinstance(domain, dict):
            raise ValueError("Domain configuration must be a non-empty dictionary")

        required_keys = ['url', 'container']
        for key in required_keys:
            if key not in domain:
                raise ValueError(f"Missing required domain configuration key: {key}")

        domain["url"] = re.sub(r'^https?://', '', domain["url"].lower())
        domain["url"] = re.sub(r'/$', '', domain["url"])

        # Validate domain format
        if not re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain["url"]):
            raise ValueError(f"Invalid domain URL format: {domain['url']}")

        # Optional port validation
        if 'port' in domain:
            if not isinstance(domain['port'], int) or domain['port'] <= 0 or domain['port'] > 65535:
                raise ValueError(f"Invalid port number: {domain['port']}")

        return domain

    def sanitize_domain_name(self, domain):
        """
        Sanitize domain name for use in Kubernetes resource names.

        Args:
            domain (str): Domain URL

        Returns:
            str: Sanitized domain name
        """

        return domain.replace('.', '-')

    def check_domain_availability(self, domain):
        """
        Check if a domain is already in use across the cluster.

        Args:
            domain (str): Domain URL to check

        Returns:
            bool: True if domain is available, False if already in use
        """
        try:
            existing_routes = KubernetesAPI.custom.list_cluster_custom_object(
                group="traefik.containo.us",
                version="v1alpha1",
                plural="ingressroutes"
            )

            for route in existing_routes['items']:
                if 'routes' in route['spec']:
                    for route_rule in route['spec']['routes']:
                        if 'match' in route_rule and f"Host(`{domain}`)" in route_rule['match']:
                            logging.warning(f" ↳ [{self.namespace}/{self.name}] Domain {domain} is already in use")
                            return False
            return True
        except ApiException as e:
            logging.error(f"Error checking domain availability: {e}")
            return False

    def generate_domain_name(self, domain):
        """
        Generate a TLS secret name for a given domain.

        Args:
            domain (str): Domain URL

        Returns:
            str: TLS secret name
        """
        return f"{domain.replace('.', '-')}-tls"

    def create_domain(self, domain):
        """
        Enhanced domain creation with more robust error handling and logging.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Resource name
            domain (dict): Domain configuration
        """
        try:
            domain = self.validate_domain(domain)

            logging.info(f" ↳ [{self.namespace}/{self.name}] Creating domain resources for {domain['url']}")

            if not self.check_domain_availability(domain['url']):
                logging.warning(f" ↳ [{self.namespace}/{self.name}] Domain {domain['url']} is already in use")
                raise ValueError(f"Domain {domain['url']} already in use")

            domain_name = self.sanitize_domain_name(domain['url'])
            service_name = self.name

            self.create_certificate(domain, domain_name),
            self.create_service(service_name, domain),
            self.create_network_policy(service_name),
            self.create_https_middleware(domain_name),
            self.create_http_ingress(service_name, domain_name, domain),
            self.create_https_ingress(service_name, domain_name, domain)

        except ValueError as e:
            logging.error(f"    ↳ [{self.namespace}/{self.name}] Error in domain creation: {e}", exc_info=True)
            raise ValueError(f"Error creating domain {domain['url']}")

        except Exception as e:
            logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating domain: {e}", exc_info=True)
            raise ValueError(f"Error creating domain {domain['url']}")

        logging.info(f"    ↳ [{self.namespace}/{self.name}] Successfully created domain resources for {domain['url']}")

    def create_certificate(self, domain, domain_name):
        """
        Create a certificate for the domain.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Resource name
            domain (dict): Domain configuration
            domain_name (str): Sanitized domain name
        """
        certificate = {
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": {
                "name": domain_name,
                "namespace": self.namespace
            },
            "spec": {
                "dnsNames": [domain['url']],
                "issuerRef": {
                    "name": "letsencrypt-prod",
                    "kind": "ClusterIssuer"
                },
                "secretName": f"{domain_name}-tls",
                "duration": "2160h",
                "renewBefore": "360h",
                "privateKey": {
                    "algorithm": "RSA",
                    "size": 2048
                }
            }
        }

        try:
            KubernetesAPI.custom.create_namespaced_custom_object(
                group="cert-manager.io",
                version="v1",
                namespace=self.namespace,
                plural="certificates",
                body=certificate
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Created certificate for domain {domain['url']}")
        except ApiException as e:
            if e.status == 409:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] Certificate already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating certificate: {e}")

    def create_service(self, service_name, domain):
        """
        Create a Kubernetes service for the domain.

        Args:
            service_name (str): Service name
            domain (dict): Domain configuration
        """
        service_ports = []
        try:
            service = KubernetesAPI.core.read_namespaced_service(
                namespace=self.namespace,
                name=service_name
            )
            service_exists = True
        except ApiException as e:
            if e.status == 404:
                service = None
                service_exists = False
            else:
                logging.error(f"Error reading service: {e}")
                return

        if service_exists:
            for port in service.spec.ports:
                service_ports.append(
                    client.V1ServicePort(
                        port=port.port,
                        target_port=port.target_port,
                        protocol=port.protocol
                    )
                )

        default_port = domain.get('port', 80)
        if not any(port.port == default_port for port in service_ports):
            service_ports.append(
                client.V1ServicePort(
                    port=default_port,
                    target_port=default_port,
                    protocol="TCP"
                )
            )

        service = client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=client.V1ObjectMeta(
                name=service_name,
                namespace=self.namespace,
                labels={"app": self.name}
            ),
            spec=client.V1ServiceSpec(
                selector={
                    "app": self.name,
                    "type": "container"
                },
                ports=service_ports,
                type="ClusterIP"
            )
        )

        try:
            if service_exists:
                KubernetesAPI.core.patch_namespaced_service(
                    namespace=self.namespace,
                    name=service_name,
                    body=service
                )
                logging.info(f"    ↳ [{self.namespace}/{self.name}] Updated service")
            else:
                KubernetesAPI.core.create_namespaced_service(
                    namespace=self.namespace,
                    body=service
                )
                logging.info(f"    ↳ [{self.namespace}/{self.name}] Created service")
        except ApiException as e:
            logging.error(f"Error creating/updating service: {e}")

    def create_network_policy(self, service_name):
        """
        Create a network policy for the domain.

        Args:
            service_name (str): Service name
        """

        service = KubernetesAPI.core.read_namespaced_service(
            namespace=self.namespace,
            name=service_name
        )

        network_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"{service_name}-web",
                "namespace": self.namespace
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "app": self.name,
                        "type": "container"
                    }
                },
                "policyTypes": ["Ingress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "kube-system"
                                    }
                                }
                            },
                            {
                               "podSelector": {
                                    "matchLabels": {
                                        "app.kubernetes.io/name": "traefik"
                                    }
                                }
                            }
                        ],
                        "ports": [
                            {
                                "port": port.port
                            }
                            for port in service.spec.ports
                        ]
                    }
                ]
            }
        }

        try:
            KubernetesAPI.networking.create_namespaced_network_policy(
                namespace=self.namespace,
                body=network_policy
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Created network policy allowing inbound traffic for app {self.name}")
        except ApiException as e:
            if e.status == 409:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] Network policy already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating network policy: {e}")

    def create_https_middleware(self, domain_name):
        """
        Create HTTPS redirection middleware.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Resource name
            domain_name (str): Sanitized domain name
        """
        middleware = {
            "apiVersion": "traefik.containo.us/v1alpha1",
            "kind": "Middleware",
            "metadata": {
                "name": f"{domain_name}-redirect",
                "namespace": self.namespace
            },
            "spec": {
                "redirectScheme": {
                    "scheme": "https",
                    "permanent": True
                }
            }
        }

        try:
            KubernetesAPI.custom.create_namespaced_custom_object(
                group="traefik.containo.us",
                version="v1alpha1",
                namespace=self.namespace,
                plural="middlewares",
                body=middleware
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Created HTTPS redirect middleware")
        except ApiException as e:
            if e.status == 409:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] Middleware redirect already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating middleware: {e}")

    def create_http_ingress(self, service_name, domain_name, domain):
        """
        Create HTTP IngressRoute for domain redirection.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Resource name
            service_name (str): Service name
            domain_name (str): Sanitized domain name
            domain (dict): Domain configuration
        """
        match_rule = f"Host(`{domain['url']}`)"

        http_route = {
            "apiVersion": "traefik.containo.us/v1alpha1",
            "kind": "IngressRoute",
            "metadata": {
                "name": f"{domain_name}-http",
                "namespace": self.namespace,
                "app": self.name
            },
            "spec": {
                "entryPoints": ["web"],
                "routes": [{
                    "match": match_rule,
                    "kind": "Rule",
                    "middlewares": [{
                        "name": f"{domain_name}-redirect",
                        "namespace": self.namespace
                    }],
                    "services": [{
                        "name": service_name,
                        "port": domain.get('port', 80)
                    }]
                }]
            }
        }

        try:
            KubernetesAPI.custom.create_namespaced_custom_object(
                group="traefik.containo.us",
                version="v1alpha1",
                namespace=self.namespace,
                plural="ingressroutes",
                body=http_route
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Created HTTP IngressRoute for {domain['url']}")
        except ApiException as e:
            if e.status == 409:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] HTTP IngressRoute {domain_name}-http already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating HTTP IngressRoute: {e}")

    def create_https_ingress(self, service_name, domain_name, domain):
        """
        Create HTTPS IngressRoute for domain.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Resource name
            service_name (str): Service name
            domain_name (str): Sanitized domain name
            domain (dict): Domain configuration
        """
        match_rule = f"Host(`{domain['url']}`)"

        https_route = {
            "apiVersion": "traefik.containo.us/v1alpha1",
            "kind": "IngressRoute",
            "metadata": {
                "name": f"{domain_name}-https",
                "namespace": self.namespace,
                "app": self.name
            },
            "spec": {
                "entryPoints": ["websecure"],
                "routes": [{
                    "match": match_rule,
                    "kind": "Rule",
                    "services": [{
                        "name": service_name,
                        "port": domain.get('port', 80)
                    }]
                }],
                "tls": {
                    "secretName": f"{domain_name}-tls",
                }
            }
        }

        try:
            KubernetesAPI.custom.create_namespaced_custom_object(
                group="traefik.containo.us",
                version="v1alpha1",
                namespace=self.namespace,
                plural="ingressroutes",
                body=https_route
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Created HTTPS IngressRoute for {domain['url']}")
        except ApiException as e:
            if e.status == 409:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] HTTPS IngressRoute {domain_name}-https already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating HTTPS IngressRoute: {e}")

    def delete_domain(self, domain):
        """
        Delete domain-related resources.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Resource name
            domain (dict): Domain configuration
        """
        try:
            domain_name = self.sanitize_domain_name(domain['url'])
            service_name = self.name

            logging.info(f" ↳ [{self.namespace}/{self.name}] Deleting domain resources for {domain['url']}")

            resources_deleted = [
                self.delete_https_ingress(domain_name),
                self.delete_http_ingress(domain_name),
                self.delete_https_middleware(domain_name),
                self.delete_service(service_name, domain),
                self.delete_network_policy(service_name),
                # self.delete_certificate(domain_name)
            ]

            if all(resources_deleted):
                logging.info(f"    ↳ [{self.namespace}/{self.name}] Successfully deleted all domain resources for {domain['url']}")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Some domain resources failed to delete for {domain['url']}")

        except ApiException as e:
            if e.status != 404:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting domain resources: {e}")

    def delete_network_policy(self, service_name):
        """
        Delete network policy for the domain.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Resource name
        """
        try:
            KubernetesAPI.networking.delete_namespaced_network_policy(
                namespace=self.namespace,
                name=f"{service_name}-web"
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Deleted network policy")
            return True
        except ApiException as e:
            if e.status == 404:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] Network policy not found")
                return True
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting network policy: {e}")
                return False

    def delete_http_ingress(self, domain_name):
        """
        Delete HTTP IngressRoute for domain redirection.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Resource name
        """
        try:
            KubernetesAPI.custom.delete_namespaced_custom_object(
                group="traefik.containo.us",
                version="v1alpha1",
                namespace=self.namespace,
                plural="ingressroutes",
                name=f"{domain_name}-http"
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Deleted HTTP IngressRoute")
            return True
        except ApiException as e:
            if e.status == 404:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] HTTP IngressRoute {domain_name}-http not found")
                return True
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting HTTP IngressRoute: {e}")
                return False

    def delete_https_ingress(self, domain_name):
        """
        Delete HTTPS IngressRoute for domain.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Resource name
        """
        try:
            KubernetesAPI.custom.delete_namespaced_custom_object(
                group="traefik.containo.us",
                version="v1alpha1",
                namespace=self.namespace,
                plural="ingressroutes",
                name=f"{domain_name}-https"
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Deleted HTTPS IngressRoute")
            return True
        except ApiException as e:
            if e.status == 404:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] HTTPS IngressRoute {domain_name}-https not found")
                return True
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting HTTPS IngressRoute: {e}")
                return False

    def delete_https_middleware(self, domain_name):
        """
        Delete HTTPS redirection middleware.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Middleware name
        """
        try:
            KubernetesAPI.custom.delete_namespaced_custom_object(
                group="traefik.containo.us",
                version="v1alpha1",
                namespace=self.namespace,
                plural="middlewares",
                name=f"{domain_name}-redirect"
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Deleted HTTPS redirect middleware")
            return True
        except ApiException as e:
            if e.status == 404:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] Middleware {domain_name}-redirect not found")
                return True
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting middleware: {e}")
                return False

    def delete_service(self, service_name, domain):
        """
        Delete a Kubernetes service for the domain.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Service name
            domain (dict): Domain configuration
        """
        try:
            KubernetesAPI.core.delete_namespaced_service(
                namespace=self.namespace,
                name=service_name
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Deleted service")
            return True
        except ApiException as e:
            if e.status == 404:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] Service not found")
                return True
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting service: {e}")
                return False

    def delete_certificate(self, domain_name):
        """
        Delete a certificate for the domain.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Certificate name
        """
        try:
            KubernetesAPI.custom.delete_namespaced_custom_object(
                group="cert-manager.io",
                version="v1",
                namespace=self.namespace,
                plural="certificates",
                name=domain_name
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Deleted certificate")
            return True
        except ApiException as e:
            if e.status == 404:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] Certificate not found")
                return True
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting certificate: {e}")
                return False
