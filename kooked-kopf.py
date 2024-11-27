# Kopf documentation : https://kopf.readthedocs.io/
#
# Run with `python3 kooked-kopf.py run -A`

import kopf
import kopf.cli
import logging
from kubernetes.client.exceptions import ApiException
from src.initialize import Initialize
from src.domain import Domain
from src.deployment import Deployment
import sys


@kopf.on.startup()
def on_kopf_startup(**kwargs):
    Initialize.ensure_crd_exists()
    Initialize.create_cluster_issuer()
    Initialize.ensure_traefik_rbac()


@kopf.on.create('kooked.ch', 'v1', 'kookedapps')
def on_create_app(spec, name, namespace, **kwargs):
    operator = KookedAppOperator(name, namespace, spec)
    operator.create_app(spec)


@kopf.on.update('kooked.ch', 'v1', 'kookedapps')
def on_update_app(spec, name, namespace, **kwargs):
    operator = KookedAppOperator(name, namespace, spec)
    operator.update_kookeddeployment(spec)


@kopf.on.delete('kooked.ch', 'v1', 'kookedapps')
def on_delete_app(spec, name, namespace, **kwargs):
    operator = KookedAppOperator(name, namespace, spec)
    operator.delete_app(spec)


class KookedAppOperator:
    def __init__(self, name, namespace, spec):
        """
        KookedAppOperator constructor

        Args:
            name (str): KookedApp name
            namespace (str): KookedApp namespace
            spec (dict): KookedApp spec
        """
        self.name = name
        self.namespace = namespace
        self.domain = Domain(name, namespace)
        self.deployment = Deployment(name, namespace)

    def create_app(self, spec):
        """
        Create KookedApp

        Args:
            spec (dict): KookedApp spec
        """
        logging.info(f"[{self.namespace}/{self.name}] Creating KookedApp")

        containers = spec.get("containers", [])
        domains = spec.get("domains", [])

        port_container_map = {}
        for domain in domains:
            container_name = domain.get("container")
            port = domain.get("port")

            if container_name not in [container["name"] for container in containers]:
                logging.error(f"[{self.namespace}/{self.name}] Error creating domain: Container '{container_name}' not found")
                return

            if port in port_container_map:
                conflicting_container = port_container_map[port]
                if conflicting_container != container_name:
                    error_msg = (f"Port {port} is used by multiple containers: {conflicting_container} and {container_name}")
                    logging.error(f"[{self.namespace}/{self.name}] {error_msg}")
                    break
            else:
                port_container_map[port] = container_name

        try:
            for domain in domains:
                self.domain.create_domain(domain)

                for container in containers:
                    if container["name"] == domain.get("container"):
                        if "ports" not in container:
                            container["ports"] = []
                        if domain.get("port") not in container["ports"]:
                            container["ports"].append(domain.get("port"))
                        break
        except ValueError as e:
            logging.error(f"[{self.namespace}/{self.name}] Error creating domain: {e}")
        except Exception as e:
            logging.error(f"[{self.namespace}/{self.name}] Unexpected error creating domain: {e}")

        try:
            self.deployment.create_deployment(containers)
        except ValueError as e:
            logging.error(f"[{self.namespace}/{self.name}] Error creating deployment: {e}")

    def update_kookeddeployment(self, spec):
        logging.info(f"[{self.namespace}/{self.name}] Updating KookedApp")

    def delete_app(self, spec):
        logging.info(f"[{self.namespace}/{self.name}] Deleting KookedApp")

        try:
            for domain in spec.get("domains", []):
                self.domain.delete_domain(domain)

            self.deployment.delete_deployment()

            logging.info(f" ↳ [{self.namespace}/{self.name}] All resources deleted successfully")
        except ApiException as e:
            logging.error(f"Error deleting resources: {e}")


if __name__ == '__main__':
    sys.exit(kopf.cli.main())
