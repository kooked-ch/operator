import logging
from kubernetes import client
from kubernetes.client.exceptions import ApiException
from src.KubernetesAPI import KubernetesAPI
import re


class Domains:
    @staticmethod
    def validate_domain(domain):
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
        domain["url"] = re.sub(r'\..*$', '', domain["url"])
        domain["url"] = re.sub(r'/$', '', domain["url"])

        # Validate URL format
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain['url']):
            raise ValueError(f"Invalid domain URL format: {domain['url']}")

        # Optional port validation
        if 'port' in domain:
            if not isinstance(domain['port'], int) or domain['port'] <= 0 or domain['port'] > 65535:
                raise ValueError(f"Invalid port number: {domain['port']}")

        return domain

    @staticmethod
    def sanitize_domain_name(domain):
        """
        Sanitize domain name for use in Kubernetes resource names.

        Args:
            domain (str): Domain URL

        Returns:
            str: Sanitized domain name
        """

        return domain.replace('.', '-')

    @staticmethod
    def check_domain_availability(domain):
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
                            logging.warning(f"Domain {domain} is already in use")
                            return False
            return True
        except ApiException as e:
            logging.error(f"Error checking domain availability: {e}")
            return False

    @staticmethod
    def generate_domain_name(domain):
        """
        Generate a TLS secret name for a given domain.

        Args:
            domain (str): Domain URL

        Returns:
            str: TLS secret name
        """
        return f"{domain.replace('.', '-')}-tls"

    @staticmethod
    def create_domain(namespace, name, domain):
        """
        Enhanced domain creation with more robust error handling and logging.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Resource name
            domain (dict): Domain configuration
        """
        try:
            # Comprehensive validation
            domain = Domains.validate_domain(domain)

            # Check domain availability with a more specific check
            if not Domains.check_domain_availability(domain['url']):
                logging.warning(f"Domain {domain['url']} is already in use")
                return False

            # Sanitize domain name for Kubernetes resources
            domain_name = Domains.sanitize_domain_name(domain['url'])
            service_name = f"{name}--{domain['container']}"

            # Create domain resources with better error tracking
            resources_created = [
                Domains.create_certificate(namespace, domain, domain_name),
                Domains.create_service(namespace, name, service_name, domain),
                Domains.create_https_middleware(namespace, domain_name),
                Domains.create_http_ingress(namespace, service_name, domain_name, domain),
                Domains.create_https_ingress(namespace, service_name, domain_name, domain)
            ]

            # Check if all resources were created successfully
            if all(resources_created):
                logging.info(f"Successfully created all domain resources for {domain['url']}")
                return True
            else:
                logging.error(f"Some domain resources failed to create for {domain['url']}")
                return False

        except Exception as e:
            logging.error(f"Comprehensive error in domain creation: {e}", exc_info=True)
            raise

    @staticmethod
    def create_certificate(namespace, domain, domain_name):
        """
        Create a certificate for the domain.

        Args:
            namespace (str): Kubernetes namespace
            domain (dict): Domain configuration
            domain_name (str): Sanitized domain name
        """
        certificate = {
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": {
                "name": domain_name,
                "namespace": namespace
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
                namespace=namespace,
                plural="certificates",
                body=certificate
            )
            logging.info(f"Created certificate for domain {domain['url']}")
        except ApiException as e:
            if e.status == 409:
                logging.info(f"Certificate {name} already exists")
            else:
                logging.error(f"Error creating certificate: {e}")

    @staticmethod
    def create_service(namespace, name, service_name, domain):
        """
        Create a Kubernetes service for the domain.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Resource name
            service_name (str): Service name
            domain (dict): Domain configuration
        """

        service_ports = []

        service = KubernetesAPI.core.read_namespaced_service(
            namespace=namespace,
            name=service_name
        )

        if service:
            logging.info(f"Service {service_name} exists, update configuration")

            service.spec.ports.forEach(lambda port: service_ports.append(
                client.V1ServicePort(
                    port=port.port,
                    target_port=port.target_port,
                    protocol=port.protocol
                )
            ))

            if not any(port.port == domain.get('port', 80) for port in service.spec.ports):
                service_ports.append(
                    client.V1ServicePort(
                        port=domain.get('port', 80),
                        target_port=domain.get('port', 80),
                        protocol="TCP"
                    )
                )

        else:
            service_ports.append(
                client.V1ServicePort(
                    port=80,
                    target_port=domain.get('port', 80),
                    protocol="TCP"
                )
            )

        service = client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=client.V1ObjectMeta(
                name=f"{service_name}",
                namespace=namespace,
                labels={"app": name, "container": domain['container']}
            ),
            spec=client.V1ServiceSpec(
                selector={"app": name, "container": domain['container']},
                ports=service_ports,
                type="ClusterIP"
            )
        )

        try:
            if service:
                KubernetesAPI.core.patch_namespaced_service(
                    namespace=namespace,
                    name=service_name,
                    body=service
                )
                logging.info(f"Updated service for {service_name} in namespace {namespace}")

            else:
                KubernetesAPI.core.create_namespaced_service(
                    namespace=namespace,
                    body=service
                )
                logging.info(f"Created service for {service_name} in namespace {namespace}")
        except ApiException as e:
            logging.error(f"Error creating service: {e}")

    @staticmethod
    def create_https_middleware(namespace, name):
        """
        Create HTTPS redirection middleware.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Middleware name
        """
        middleware = {
            "apiVersion": "traefik.containo.us/v1alpha1",
            "kind": "Middleware",
            "metadata": {
                "name": f"{name}-redirect",
                "namespace": namespace
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
                namespace=namespace,
                plural="middlewares",
                body=middleware
            )
            logging.info(f"Created HTTPS redirect middleware for {name}")
        except ApiException as e:
            if e.status == 409:
                logging.info(f"Middleware {name}-redirect already exists")
            else:
                logging.error(f"Error creating middleware: {e}")

    @staticmethod
    def create_http_ingress(namespace, service_name, domain_name, domain):
        """
        Create HTTP IngressRoute for domain redirection.

        Args:
            namespace (str): Kubernetes namespace
            domain_name (str): Sanitized domain name
            domain (dict): Domain configuration
        """
        match_rule = f"Host(`{domain['url']}`)"

        http_route = {
            "apiVersion": "traefik.containo.us/v1alpha1",
            "kind": "IngressRoute",
            "metadata": {
                "name": f"{domain_name}-http",
                "namespace": namespace
            },
            "spec": {
                "entryPoints": ["web"],
                "routes": [{
                    "match": match_rule,
                    "kind": "Rule",
                    "middlewares": [{
                        "name": f"{domain_name}-redirect",
                        "namespace": namespace
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
                namespace=namespace,
                plural="ingressroutes",
                body=http_route
            )
            logging.info(f"Created HTTP IngressRoute for {domain['url']}")
        except ApiException as e:
            if e.status == 409:
                logging.info(f"HTTP IngressRoute {domain_name}-http already exists")
            else:
                logging.error(f"Error creating HTTP IngressRoute: {e}")

    @staticmethod
    def create_https_ingress(namespace, service_name, domain_name, domain):
        """
        Create HTTPS IngressRoute for domain.

        Args:
            namespace (str): Kubernetes namespace
            domain_name (str): Sanitized domain name
            domain (dict): Domain configuration
        """
        match_rule = f"Host(`{domain['url']}`)"

        https_route = {
            "apiVersion": "traefik.containo.us/v1alpha1",
            "kind": "IngressRoute",
            "metadata": {
                "name": f"{domain_name}-https",
                "namespace": namespace
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
                namespace=namespace,
                plural="ingressroutes",
                body=https_route
            )
            logging.info(f"Created HTTPS IngressRoute for {domain['url']}")
        except ApiException as e:
            if e.status == 409:
                logging.info(f"HTTPS IngressRoute {domain_name}-https already exists")
            else:
                logging.error(f"Error creating HTTPS IngressRoute: {e}")

    @staticmethod
    def delete_domain_resources(namespace, name, domain):
        """
        Delete domain-related resources.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Resource name
            domain (dict): Domain configuration
        """
        try:
            sanitized_domain = Domains.sanitize_domain_name(domain['url'])
            domain_name = f"{sanitized_domain}-domain"

            # Delete resources in reverse order of creation
            resources_deleted = [
                Domains.delete_https_ingress(namespace, name),
                Domains.delete_http_ingress(namespace, name),
                Domains.delete_https_middleware(namespace, domain_name),
                Domains.delete_service(namespace, name, domain),
                Domains.delete_certificate(namespace, domain_name)
            ]

            # Check if all resources were deleted successfully
            if all(resources_deleted):
                logging.info(f"Successfully deleted all domain resources for {domain['url']}")
            else:
                logging.error(f"Some domain resources failed to delete for {domain['url']}")

        except ApiException as e:
            if e.status != 404:
                logging.error(f"Error deleting domain resources: {e}")

    @staticmethod
    def delete_http_ingress(namespace, name):
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
                namespace=namespace,
                plural="ingressroutes",
                name=f"{name}-http"
            )
            logging.info(f"Deleted HTTP IngressRoute for {name}")
            return True
        except ApiException as e:
            if e.status == 404:
                logging.info(f"HTTP IngressRoute {name}-http not found")
                return True
            else:
                logging.error(f"Error deleting HTTP IngressRoute: {e}")
                return False

    @staticmethod
    def delete_https_ingress(namespace, name):
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
                namespace=namespace,
                plural="ingressroutes",
                name=f"{name}-https"
            )
            logging.info(f"Deleted HTTPS IngressRoute for {name}")
            return True
        except ApiException as e:
            if e.status == 404:
                logging.info(f"HTTPS IngressRoute {name}-https not found")
                return True
            else:
                logging.error(f"Error deleting HTTPS IngressRoute: {e}")
                return False

    @staticmethod
    def delete_https_middleware(namespace, name):
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
                namespace=namespace,
                plural="middlewares",
                name=f"{name}-redirect"
            )
            logging.info(f"Deleted HTTPS redirect middleware for {name}")
            return True
        except ApiException as e:
            if e.status == 404:
                logging.info(f"Middleware {name}-redirect not found")
                return True
            else:
                logging.error(f"Error deleting middleware: {e}")
                return False

    @staticmethod
    def delete_service(namespace, name, domain):
        """
        Delete a Kubernetes service for the domain.

        Args:
            namespace (str): Kubernetes namespace
            name (str): Service name
            domain (dict): Domain configuration
        """
        try:
            KubernetesAPI.core.delete_namespaced_service(
                namespace=namespace,
                name=f"{name}--{domain['url']}"
            )
            logging.info(f"Deleted service for {name} in namespace {namespace}")
            return True
        except ApiException as e:
            if e.status == 404:
                logging.info(f"Service {name} not found")
                return True
            else:
                logging.error(f"Error deleting service: {e}")
                return False

    @staticmethod
    def delete_certificate(namespace, name):
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
                namespace=namespace,
                plural="certificates",
                name=name
            )
            logging.info(f"Deleted certificate {name}")
            return True
        except ApiException as e:
            if e.status == 404:
                logging.info(f"Certificate {name} not found")
                return True
            else:
                logging.error(f"Error deleting certificate: {e}")
                return False
