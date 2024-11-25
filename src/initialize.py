import logging
from typing import Dict, Any

from kubernetes import client
from kubernetes.client.rest import ApiException
import yaml

from src.KubernetesAPI import KubernetesAPI


class Initialize:
    """
    class for initialize Kubernetes custom resources and configurations.
    """

    @classmethod
    def ensure_crd_exists(cls) -> bool:
        """
        Ensure the Custom Resource Definition (CRD) for KookedApp exists.

        Returns:
            bool: True if CRD exists or is created successfully, False otherwise.
        """
        dyn_client = KubernetesAPI.dynamic
        api_extensions_instance = KubernetesAPI.extensions
        crd_name = "kookedapps.kooked.ch"

        try:
            crd_list = api_extensions_instance.list_custom_resource_definition()
            crd_exists = any(crd.metadata.name == crd_name for crd in crd_list.items)

            if crd_exists:
                return cls._handle_existing_crd(api_extensions_instance, crd_list, crd_name)
            else:
                return cls._create_new_crd(dyn_client, crd_name)

        except ApiException as e:
            logging.error(f"Error verifying CRD file: {e}")
            return False

    @classmethod
    def _handle_existing_crd(cls, api_extensions_instance, crd_list, crd_name: str) -> bool:
        """
        Handle an existing Custom Resource Definition.

        Args:
            api_extensions_instance: Kubernetes API extensions instance
            crd_list: List of existing CRDs
            crd_name: Name of the CRD to check

        Returns:
            bool: True if CRD is up-to-date or successfully updated
        """
        existing_crd = next(crd for crd in crd_list.items if crd.metadata.name == crd_name)

        try:
            with open("./KookedApp-crd.yaml") as file:
                new_crd_file = yaml.safe_load(file)

            if existing_crd.spec != new_crd_file['spec']:
                logging.info(f"CRD '{crd_name}' exists but has changed, updating it...")
                api_extensions_instance.patch_custom_resource_definition(
                    name=crd_name,
                    body=new_crd_file
                )
                logging.info(f"CRD '{crd_name}' updated successfully.")
            else:
                logging.info(f"CRD '{crd_name}' already exists and is up-to-date.")

            return True

        except client.exceptions.ApiException as e:
            logging.error(f"Error updating CRD: {e}")
            return False

    @classmethod
    def _create_new_crd(cls, dyn_client, crd_name: str) -> bool:
        """
        Create a new Custom Resource Definition.

        Args:
            dyn_client: Dynamic Kubernetes client
            crd_name: Name of the CRD to create

        Returns:
            bool: True if CRD is created successfully
        """
        logging.info(f"CRD '{crd_name}' does not exist, creating it...")

        try:
            with open("./KookedApp-crd.yaml") as file:
                crd_file = yaml.safe_load(file)

            crd_resource = dyn_client.resources.get(
                api_version='apiextensions.k8s.io/v1',
                kind='CustomResourceDefinition'
            )
            crd_resource.create(body=crd_file)
            logging.info(f"CRD '{crd_name}' created.")
            return True

        except client.exceptions.ApiException as e:
            logging.error(f"Error creating CRD: {e}")
            return False

    @classmethod
    def create_cluster_issuer(cls) -> None:
        """
        Create a Let's Encrypt ClusterIssuer for certificate management.
        """
        logging.info("Creating Let's Encrypt ClusterIssuer")

        cluster_issuer = _create_cluster_issuer_manifest()

        try:
            cls._check_or_create_cluster_issuer(cluster_issuer)
        except ApiException as e:
            logging.error(f"Error creating ClusterIssuer: {e}")

    @classmethod
    def _check_or_create_cluster_issuer(cls, cluster_issuer: Dict[str, Any]) -> None:
        """
        Check if ClusterIssuer exists, create if not.

        Args:
            cluster_issuer: ClusterIssuer manifest dictionary
        """
        try:
            KubernetesAPI.custom.get_cluster_custom_object(
                group="cert-manager.io",
                version="v1",
                plural="clusterissuers",
                name="letsencrypt-prod"
            )
            logging.info("ClusterIssuer 'letsencrypt-prod' already exists")
            return
        except ApiException as e:
            if e.status != 404:
                logging.error(f"Error checking for existing ClusterIssuer: {e}")
                raise

        logging.info("Creating ClusterIssuer 'letsencrypt-prod'...")
        KubernetesAPI.custom.create_cluster_custom_object(
            group="cert-manager.io",
            version="v1",
            plural="clusterissuers",
            body=cluster_issuer
        )
        logging.info("ClusterIssuer 'letsencrypt-prod' created successfully")

    @classmethod
    def ensure_traefik_rbac(cls) -> bool:
        """
        Set up Traefik RBAC for cross-namespace IngressRoute access.

        Returns:
            bool: True if RBAC is configured successfully
        """
        logging.info("Setting up Traefik RBAC for cross-namespace IngressRoute access")

        cluster_role = _create_traefik_cluster_role_manifest()
        cluster_role_binding = _create_traefik_cluster_role_binding_manifest()

        try:
            cls._manage_cluster_role(cluster_role)
            cls._manage_cluster_role_binding(cluster_role_binding)

            logging.info("Successfully configured Traefik RBAC for cross-namespace access")
            return True

        except ApiException as e:
            logging.error(f"Error configuring Traefik RBAC: {e}")
            return False

    @classmethod
    def _manage_cluster_role(cls, cluster_role: Dict[str, Any]) -> None:
        """
        Manage the Traefik ClusterRole, creating or updating as needed.

        Args:
            cluster_role: ClusterRole manifest dictionary
        """
        try:
            KubernetesAPI.custom.get_cluster_custom_object(
                group="rbac.authorization.k8s.io",
                version="v1",
                plural="clusterroles",
                name="traefik-ingress-controller"
            )
            logging.info("ClusterRole exists, updating if needed...")
            KubernetesAPI.custom.patch_cluster_custom_object(
                group="rbac.authorization.k8s.io",
                version="v1",
                plural="clusterroles",
                name="traefik-ingress-controller",
                body=cluster_role
            )
        except ApiException as e:
            if e.status == 404:
                logging.info("ClusterRole does not exist, creating it...")
                KubernetesAPI.custom.create_cluster_custom_object(
                    group="rbac.authorization.k8s.io",
                    version="v1",
                    plural="clusterroles",
                    body=cluster_role
                )
            else:
                raise

    @classmethod
    def _manage_cluster_role_binding(cls, cluster_role_binding: Dict[str, Any]) -> None:
        """
        Manage the Traefik ClusterRoleBinding, creating or updating as needed.

        Args:
            cluster_role_binding: ClusterRoleBinding manifest dictionary
        """
        try:
            KubernetesAPI.custom.get_cluster_custom_object(
                group="rbac.authorization.k8s.io",
                version="v1",
                plural="clusterrolebindings",
                name="traefik-ingress-controller"
            )
            logging.info("ClusterRoleBinding exists, updating if needed...")
            KubernetesAPI.custom.patch_cluster_custom_object(
                group="rbac.authorization.k8s.io",
                version="v1",
                plural="clusterrolebindings",
                name="traefik-ingress-controller",
                body=cluster_role_binding
            )
        except ApiException as e:
            if e.status == 404:
                logging.info("ClusterRoleBinding does not exist, creating it...")
                KubernetesAPI.custom.create_cluster_custom_object(
                    group="rbac.authorization.k8s.io",
                    version="v1",
                    plural="clusterrolebindings",
                    body=cluster_role_binding
                )
            else:
                raise


def _create_cluster_issuer_manifest() -> Dict[str, Any]:
    """
    Create the Let's Encrypt ClusterIssuer manifest.

    Returns:
        Dict[str, Any]: ClusterIssuer configuration dictionary
    """
    return {
        "apiVersion": "cert-manager.io/v1",
        "kind": "ClusterIssuer",
        "metadata": {
            "name": "letsencrypt-prod",
        },
        "spec": {
            "acme": {
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "email": "admin@kooked.ch",
                "privateKeySecretRef": {
                    "name": "letsencrypt-prod-key"
                },
                "solvers": [
                    {
                        "http01": {
                            "ingress": {
                                "class": "traefik"
                            }
                        }
                    }
                ]
            }
        }
    }


def _create_traefik_cluster_role_manifest() -> Dict[str, Any]:
    """
    Create the Traefik ClusterRole manifest.

    Returns:
        Dict[str, Any]: ClusterRole configuration dictionary
    """
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {
            "name": "traefik-ingress-controller"
        },
        "rules": [
            {
                "apiGroups": [""],
                "resources": ["services", "endpoints", "secrets"],
                "verbs": ["get", "list", "watch"]
            },
            {
                "apiGroups": ["traefik.containo.us"],
                "resources": [
                    "ingressroutes",
                    "ingressroutetcps",
                    "ingressrouteudps",
                    "middlewares",
                    "tlsoptions",
                    "tlsstores",
                    "serverstransports"
                ],
                "verbs": ["get", "list", "watch"]
            }
        ]
    }


def _create_traefik_cluster_role_binding_manifest() -> Dict[str, Any]:
    """
    Create the Traefik ClusterRoleBinding manifest.

    Returns:
        Dict[str, Any]: ClusterRoleBinding configuration dictionary
    """
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {
            "name": "traefik-ingress-controller"
        },
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": "traefik-ingress-controller"
        },
        "subjects": [
            {
                "kind": "ServiceAccount",
                "name": "traefik",
                "namespace": "kube-system"
            }
        ]
    }
