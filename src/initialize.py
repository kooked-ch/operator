from kubernetes import client
from kubernetes.client.rest import ApiException
from src.KubernetesAPI import KubernetesAPI
import logging
import yaml


class KookedAppStartOperator:
    @classmethod
    def ensure_crd_exists(cls):
        dyn_client = KubernetesAPI.dynamic
        api_extensions_instance = KubernetesAPI.extensions
        crd_name = "kookedapps.kooked.ch"

        try:
            crd_list = api_extensions_instance.list_custom_resource_definition()
            crd_exists = any(crd.metadata.name == crd_name for crd in crd_list.items)

            if crd_exists:
                existing_crd = next(crd for crd in crd_list.items if crd.metadata.name == crd_name)
                with open("./KookedApp-crd.yaml") as file:
                    new_crd_file = yaml.safe_load(file)

                if existing_crd.spec != new_crd_file['spec']:
                    logging.info(f"CRD '{crd_name}' exists but has changed, updating it...")
                    try:
                        api_extensions_instance.patch_custom_resource_definition(
                            name=crd_name,
                            body=new_crd_file
                        )
                        logging.info(f"CRD '{crd_name}' updated successfully.")
                    except client.exceptions.ApiException as e:
                        logging.error("Error trying to update CRD :", e)
                else:
                    logging.info(f"CRD '{crd_name}' already exists and is up-to-date, doing nothing...")
                return True

            else:
                logging.info(f"CRD '{crd_name}' does not exist, creating it...")
                with open("./KookedApp-crd.yaml") as file:
                    crd_file = yaml.safe_load(file)
                crd_resource = dyn_client.resources.get(api_version='apiextensions.k8s.io/v1', kind='CustomResourceDefinition')

                try:
                    crd_resource.create(body=crd_file)
                    logging.info(f"CRD '{crd_name}' created.")
                except client.exceptions.ApiException as e:
                    logging.error("Error trying to create CRD :", e)

        except ApiException as e:
            logging.error(f"Error verifying CRD file: {e}")

        return False

    @classmethod
    def create_cluster_issuer(cls):
        logging.info("Creating Let's Encrypt ClusterIssuer")

        cluster_issuer = {
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

        try:
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
                if e.status == 404:
                    logging.info("ClusterIssuer 'letsencrypt-prod' does not exist, proceeding to create it.")
                else:
                    logging.error(f"Error checking for existing ClusterIssuer: {e}")
                    raise e

            logging.info("Creating ClusterIssuer 'letsencrypt-prod'...")
            KubernetesAPI.custom.create_cluster_custom_object(
                group="cert-manager.io",
                version="v1",
                plural="clusterissuers",
                body=cluster_issuer
            )
            logging.info("ClusterIssuer 'letsencrypt-prod' created successfully")

        except ApiException as e:
            logging.error(f"Error creating ClusterIssuer: {e}")

    @classmethod
    def ensure_traefik_rbac(cls):
        logging.info("Setting up Traefik RBAC for cross-namespace IngressRoute access")

        cluster_role = {
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

        cluster_role_binding = {
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

        try:
            try:
                existing_role = KubernetesAPI.custom.get_cluster_custom_object(
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
                    raise e

            try:
                existing_binding = KubernetesAPI.custom.get_cluster_custom_object(
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
                    raise e

            logging.info("Successfully configured Traefik RBAC for cross-namespace access")
            return True

        except ApiException as e:
            logging.error(f"Error configuring Traefik RBAC: {e}")
            return False
