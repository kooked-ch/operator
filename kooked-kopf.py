import kopf
import kopf.cli
import logging
from kubernetes.client.exceptions import ApiException
from src.initialize import Initialize
from src.domain import Domain
from src.deployment import Deployment
from src.databases import Databases
import sys


@kopf.on.startup()
def on_kopf_startup(**kwargs):
    Initialize.ensure_crd_exists()
    Initialize.create_cluster_issuer()
    Initialize.ensure_traefik_rbac()


@kopf.on.create('kooked.ch', 'v1', 'kookedapps', retries=3)
def on_create_app(spec, name, namespace, **kwargs):
    operator = KookedAppOperator(name, namespace, spec)
    try:
        operator.create_app(spec)
    except ValueError as e:
        raise kopf.TemporaryError(
            e, delay=120
        )
    except Exception as e:
        logging.error(f"[{namespace}/{name}] Error during app creation: {e}")
        raise kopf.TemporaryError(
            "An unexpected error occurred when creating the application."
        )


@kopf.on.update('kooked.ch', 'v1', 'kookedapps')
def on_update_app(spec, name, namespace, **kwargs):
    operator = KookedAppOperator(name, namespace, spec)
    try:
        operator.update_kookeddeployment(spec)
    except ValueError as e:
        raise kopf.TemporaryError(
            e, delay=120, backoff=2
        )
    except Exception as e:
        logging.error(f"[{namespace}/{name}] Error during app creation: {e}")
        raise kopf.TemporaryError(
            "An unexpected error occurred when creating the application.",
            backoff=0
        )


@kopf.on.delete('kooked.ch', 'v1', 'kookedapps')
def on_delete_app(spec, name, namespace, **kwargs):
    operator = KookedAppOperator(name, namespace, spec)
    try:
        operator.delete_app(spec)
    except ValueError as e:
        raise kopf.TemporaryError(
            e, delay=120, backoff=2
        )
    except Exception as e:
        logging.error(f"[{namespace}/{name}] Error during app creation: {e}")
        raise kopf.TemporaryError(
            "An unexpected error occurred when creating the application.",
            backoff=0
        )


class KookedAppOperator:
    def __init__(self, name, namespace, spec):
        self.name = name
        self.namespace = namespace
        self.domain = Domain(name, namespace)
        self.deployment = Deployment(name, namespace)
        self.databases = Databases(name, namespace)

    def create_app(self, spec):
        logging.info(f"[{self.namespace}/{self.name}] Creating KookedApp")
        containers = spec.get("containers", [])
        domains = spec.get("domains", [])

        port_container_map = {}
        for domain in domains:
            container_name = domain.get("container")
            port = domain.get("port")

            if container_name not in [container["name"] for container in containers]:
                error_msg = f"Container '{container_name}' not found for domain"
                logging.error(f"[{self.namespace}/{self.name}] {error_msg}")
                raise ValueError(error_msg)

            if port in port_container_map:
                conflicting_container = port_container_map[port]
                if conflicting_container != container_name:
                    error_msg = (f"Port {port} is used by multiple containers: {conflicting_container} and {container_name}")
                    logging.error(f"[{self.namespace}/{self.name}] {error_msg}")
                    raise ValueError(error_msg)
            else:
                port_container_map[port] = container_name

        for domain in domains:
            self.domain.create_domain(domain)

            for container in containers:
                if container["name"] == domain.get("container"):
                    if "ports" not in container:
                        container["ports"] = []
                    if domain.get("port") not in container["ports"]:
                        container["ports"].append(domain.get("port"))
                    break

        self.deployment.create_deployment(containers)

        for database in spec.get("databases", []):
            self.databases.create_database(database)

        logging.info(f" ↳ [{self.namespace}/{self.name}] KookedApp created successfully")

    def update_kookeddeployment(self, spec):
        logging.info(f"[{self.namespace}/{self.name}] Updating KookedApp")
        # Ajoutez votre logique de mise à jour ici

    def delete_app(self, spec):
        logging.info(f"[{self.namespace}/{self.name}] Deleting KookedApp")
        try:
            for domain in spec.get("domains", []):
                self.domain.delete_domain(domain)
            self.deployment.delete_deployment()

            for database in spec.get("databases", []):
                self.databases.delete_database(database)
            logging.info(f" ↳ [{self.namespace}/{self.name}] All resources deleted successfully")
        except ApiException as e:
            logging.error(f"[{self.namespace}/{self.name}] Error deleting resources: {e}")
            raise


if __name__ == '__main__':
    sys.exit(kopf.cli.main())
