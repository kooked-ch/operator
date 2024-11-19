# Kopf documentation : https://kopf.readthedocs.io/
#
# Run with `python3 kooked-kopf.py run -A`
#
import kopf
import kopf.cli
import logging
from kubernetes import client, config
from kubernetes.dynamic import DynamicClient
from kubernetes.client.exceptions import ApiException
import os
import sys
import yaml


@kopf.on.startup()
def on_kopf_startup(**kwargs):
    KookedDeploymentStartOperator.ensure_crd_exists()
    KookedDeploymentStartOperator.create_cluster_issuer()
    KookedDeploymentStartOperator.ensure_traefik_rbac()


@kopf.on.create('kooked.ch', 'v1', 'kookeddeployments')
def on_create_kookeddeployment(spec, name, namespace, **kwargs):
    operator = KookedDeploymentOperator(name, namespace, spec)
    operator.create_kookeddeployment(spec)


@kopf.on.update('kooked.ch', 'v1', 'kookeddeployments')
def on_update_kookeddeployment(spec, name, namespace, **kwargs):
    operator = KookedDeploymentOperator(name, namespace, spec)
    operator.update_kookeddeployment(spec)


@kopf.on.delete('kooked.ch', 'v1', 'kookeddeployments')
def on_delete_kookeddeployment(spec, name, namespace, **kwargs):
    operator = KookedDeploymentOperator(name, namespace, spec)
    operator.delete_kookeddeployment(spec)


class classproperty:
    def __init__(self, func):
        self.fget = func

    def __get__(self, instance, owner):
        return self.fget(owner)


class KubernetesAPI:
    __singleton = None

    @classmethod
    def __get(cls):
        if cls.__singleton is None:
            cls.__singleton = cls()

        return cls.__singleton

    def __init__(self):

        token_path = '/var/run/secrets/kubernetes.io/serviceaccount/token'
        if os.path.exists(token_path):
            config.load_incluster_config()
        else:
            config.load_kube_config()

        self._custom = client.CustomObjectsApi()
        self._core = client.CoreV1Api()
        self._extensions = client.ApiextensionsV1Api()
        self._dynamic = DynamicClient(client.ApiClient())
        self._networking = client.NetworkingV1Api()
        self._apps = client.AppsV1Api()

    @classproperty
    def custom(cls):
        return cls.__get()._custom

    @classproperty
    def core(cls):
        return cls.__get()._core

    @classproperty
    def extensions(cls):
        return cls.__get()._extensions

    @classproperty
    def dynamic(cls):
        return cls.__get()._dynamic

    @classproperty
    def networking(cls):
        return cls.__get()._networking

    @classproperty
    def apps(cls):
        return cls.__get()._apps


class KookedDeploymentOperator:
    def __init__(self, name, namespace, spec):
        self.name = name
        self.namespace = namespace

    def write_event(self, event):
        try:
            KubernetesAPI.core.create_namespaced_event(
                namespace=self.namespace,
                body={
                    'metadata': {
                        'generateName': f"{self.name}-event-"
                    },
                    'involvedObject': {
                        'kind': 'KookedDeployment',
                        'name': self.name,
                        'namespace': self.namespace
                    },
                    'type': event['type'],
                    'reason': event['reason'],
                    'message': event['message']
                }
            )
        except Exception as e:
            logging.error(f"Could not write event: {e}")

    def update_status(self, status):
        try:
            KubernetesAPI.custom.patch_namespaced_custom_object_status(
                group="kooked.ch",
                version="v1",
                plural="kookeddeployments",
                name=self.name,
                namespace=self.namespace,
                body={"status": status}
            )
        except ApiException as e:
            logging.error(f"Could not update status: {e}")

    def check_domain(self, domain):
        all_deployments = KubernetesAPI.custom.list_cluster_custom_object(
            group="kooked.ch",
            version="v1",
            plural="kookeddeployments"
        )['items']

        domains = []

        for deployment in all_deployments:
            if deployment['metadata']['name'] == self.name:
                continue
            for container in deployment.get('containers', []):
                for domain in container.get('domains', []):
                    domains.append(domain['url'])

        if domain in domains:
            logging.error(
                f" ↳ [{self.namespace}/{self.name}] Domain '{domain}' is already in use by another KookedDeployment"
            )
            return False

    def expose_containers(self, containers):
        for container in containers:
            if container.get('domains') is None:
                continue

            self.create_service(container)
            for domain in container.get('domains', []):
                if self.check_domain(domain['url']):
                    self.create_certificate(domain['url'])
                    self.create_ingress_routes(domain['url'])

    def create_service(self, container):
        logging.info(f" ↳ [{self.namespace}/{self.name}] Creating service")

        service_ports = []
        for domain in container.get('domains', []):
            service_ports.append(
                client.V1ServicePort(
                    port=80,
                    target_port=domain.get('port', 80),
                    protocol="TCP"
                )
            )

        if not service_ports:
            logging.info(
                f" ↳ [{self.namespace}/{self.name}] No service ports to create"
            )
            return

        service = client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=client.V1ObjectMeta(
                name=self.name,
                namespace=self.namespace,
                labels={"app": self.name}
            ),
            spec=client.V1ServiceSpec(
                selector={"app": self.name},
                ports=service_ports,
                type="ClusterIP"
            )
        )

        try:
            KubernetesAPI.core.create_namespaced_service(
                namespace=self.namespace,
                body=service
            )
            logging.info(f" ↳ [{self.namespace}/{self.name}] Service created successfully")
        except ApiException as e:
            if e.status == 409:
                logging.info(f" ↳ [{self.namespace}/{self.name}] Service already exists")
            else:
                logging.error(f"Error creating service: {e}")

    def create_certificate(self, domain):
        logging.info(f" ↳ [{self.namespace}/{self.name}] Creating TLS certificate for {domain}")

        certificate = {
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": {
                "name": domain.replace('.', '-'),
                "namespace": self.namespace
            },
            "spec": {
                "dnsNames": [domain],
                "issuerRef": {
                    "name": "letsencrypt-prod",
                    "kind": "ClusterIssuer"
                },
                "secretName": f"{domain.replace('.', '-')}-tls",
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
            logging.info(f" ↳ [{self.namespace}/{self.name}] Certificate created successfully")
        except ApiException as e:
            if e.status == 409:
                logging.info(f" ↳ [{self.namespace}/{self.name}] Certificate already exists")
            else:
                logging.error(f"Error creating certificate: {e}")

    def create_ingress_routes(self, domain):
        logging.info(f" ↳ [{self.namespace}/{self.name}] Creating IngressRoutes for {domain.url}")

        # List to store middleware to create
        middlewares_to_create = []

        # Create HTTP IngressRoute (for redirect)
        http_route = {
            "apiVersion": "traefik.containo.us/v1alpha1",
            "kind": "IngressRoute",
            "metadata": {
                "name": f"{domain.replace('.', '-')}-http",
                "namespace": self.namespace
            },
            "spec": {
                "entryPoints": ["web"],
                "routes": [{
                    "match": f"Host(`{domain}`)",
                    "kind": "Rule",
                    "middlewares": [{
                        "name": f"{domain.replace('.', '-')}-redirect",
                        "namespace": self.namespace
                    }],
                    "services": [{
                        "name": self.name,
                        "port": 80
                    }]
                }]
            }
        }

        # Create HTTPS IngressRoute
        https_route = {
            "apiVersion": "traefik.containo.us/v1alpha1",
            "kind": "IngressRoute",
            "metadata": {
                "name": f"{domain.replace('.', '-')}-https",
                "namespace": self.namespace
            },
            "spec": {
                "entryPoints": ["websecure"],
                "routes": [{
                    "match": match_rule,
                    "kind": "Rule",
                    "services": [{
                        "name": self.name,
                        "port": 80
                    }]
                }],
                "tls": {
                    "secretName": f"{domain.replace('.', '-')}-tls"
                }
            }
        }

        resources_to_create = middlewares_to_create + [
            ("ingressroutes", http_route, "HTTP IngressRoute"),
            ("ingressroutes", https_route, "HTTPS IngressRoute")
        ]

        for plural, resource, resource_type in resources_to_create:
            try:
                KubernetesAPI.custom.create_namespaced_custom_object(
                    group="traefik.containo.us",
                    version="v1alpha1",
                    namespace=self.namespace,
                    plural=plural,
                    body=resource
                )
                logging.info(f"   ↳ [{self.namespace}/{self.name}] {resource_type} created successfully")
            except ApiException as e:
                if e.status == 409:
                    logging.info(f"   ↳ [{self.namespace}/{self.name}] {resource_type} already exists")
                else:
                    logging.error(f"Error creating {resource_type}: {e}")

    def create_deployment(self, spec):
        logging.info(f" ↳ [{self.namespace}/{self.name}] Creating deployment")

        containers = []
        for container_spec in spec.get('containers', []):
            container = client.V1Container(
                name=container_spec['name'],
                image=container_spec['image'],
                ports=[client.V1ContainerPort(container_port=domain.get('port', 80)) 
                       for domain in container_spec.get('domains', [])],
                env=[client.V1EnvVar(name=env['name'], value=env['value'])
                     for env in container_spec.get('environment', [])]
            )
            containers.append(container)

            # Create service and ingress for container if it has domains
            if container_spec.get('domains'):
                self.create_service(container_spec)
                for domain in container_spec['domains']:
                    self.create_certificate(domain['url'])
                    self.create_ingress_routes(domain['url'], domain.get('port', 80))

        deployment = client.V1Deployment(
            api_version="apps/v1",
            kind="Deployment",
            metadata=client.V1ObjectMeta(
                name=self.name,
                namespace=self.namespace,
                labels={"app": self.name}
            ),
            spec=client.V1DeploymentSpec(
                replicas=spec.get('replicas', 1),
                selector=client.V1LabelSelector(
                    match_labels={"app": self.name}
                ),
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(
                        labels={"app": self.name}
                    ),
                    spec=client.V1PodSpec(
                        containers=containers
                    )
                )
            )
        )

        try:
            KubernetesAPI.apps.create_namespaced_deployment(
                namespace=self.namespace,
                body=deployment
            )
            logging.info(f" ↳ [{self.namespace}/{self.name}] Deployment created successfully")
        except ApiException as e:
            logging.error(f"Error creating deployment: {e}")

    def create_kookeddeployment(self, spec):
        logging.info(f"[{self.namespace}/{self.name}] Creating KookedDeployment")

        # Collect all domains across containers
        all_domains = [
            domain
            for container in spec.get('containers', [])
            for domain in container.get('domains', [])
        ]

        # Validate domain uniqueness
        conflicting_domains, allowed_domains = self.validate_domain_uniqueness(all_domains)

        # Log conflicts and prevent processing if domains are already in use
        if conflicting_domains:
            self.log_domain_conflict_event(conflicting_domains)
            logging.warning(f"Skipping deployment due to domain conflicts: {conflicting_domains}")
            return

        # Update spec with allowed domains
        for container in spec.get('containers', []):
            container['domains'] = [
                domain for domain in container.get('domains', [])
                if domain in allowed_domains
            ]

        # Proceed with deployment creation
        self.create_deployment(spec)

    def update_kookeddeployment(self, spec):
        logging.info(f"[{self.namespace}/{self.name}] Updating KookedDeployment")

        # Collect all domains across containers
        all_domains = [
            domain
            for container in spec.get('containers', [])
            for domain in container.get('domains', [])
        ]

        # Validate domain uniqueness
        conflicting_domains, allowed_domains = self.validate_domain_uniqueness(all_domains)

        # Log conflicts
        if conflicting_domains:
            self.log_domain_conflict_event(conflicting_domains)

        # Update spec with allowed domains
        for container in spec.get('containers', []):
            container['domains'] = [
                domain for domain in container.get('domains', [])
                if domain in allowed_domains
            ]

            if container['domains']:
                self.create_service(container)
                for domain in container['domains']:
                    self.create_certificate(domain['url'])
                    self.create_ingress_routes(domain['url'], domain.get('port', 80))

        containers = []
        for container_spec in spec.get('containers', []):
            container = client.V1Container(
                name=container_spec['name'],
                image=container_spec['image'],
                ports=[client.V1ContainerPort(container_port=domain.get('port', 80))
                       for domain in container_spec.get('domains', [])],
                env=[client.V1EnvVar(name=env['name'], value=env['value'])
                     for env in container_spec.get('environment', [])]
            )
            containers.append(container)
            
        KubernetesAPI.apps.replace_namespaced_deployment(
            name=self.name,
            namespace=self.namespace,
            body=client.V1DeploymentSpec(
                replicas=spec.get('replicas', 1),
                selector=client.V1LabelSelector(
                    match_labels={"app": self.name}
                ),
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(
                        labels={"app": self.name}
                    ),
                    spec=client.V1PodSpec(
                        containers=containers
                    )
                )
            )
        )

    def delete_kookeddeployment(self, spec):
        logging.info(f"[{self.namespace}/{self.name}] Deleting KookedDeployment")

        try:
            # Delete Deployment
            KubernetesAPI.apps.delete_namespaced_deployment(
                name=self.name,
                namespace=self.namespace
            )

            logging.info(f" ↳ [{self.namespace}/{self.name}] Deployment deleted successfully")

            # Delete Service
            KubernetesAPI.core.delete_namespaced_service(
                name=self.name,
                namespace=self.namespace
            )

            logging.info(f" ↳ [{self.namespace}/{self.name}] Service deleted successfully")

            # Delete Certificate
            KubernetesAPI.custom.delete_namespaced_custom_object(
                group="cert-manager.io",
                version="v1",
                namespace=self.namespace,
                plural="certificates",
                name=self.name
            )

            logging.info(f" ↳ [{self.namespace}/{self.name}] Certificate deleted successfully")

            # Delete IngressRoutes
            for suffix in ['-http', '-https']:
                KubernetesAPI.custom.delete_namespaced_custom_object(
                    group="traefik.containo.us",
                    version="v1alpha1",
                    namespace=self.namespace,
                    plural="ingressroutes",
                    name=f"{self.name}{suffix}"
                )

            logging.info(f" ↳ [{self.namespace}/{self.name}] IngressRoutes deleted successfully")

            # Delete Middleware
            KubernetesAPI.custom.delete_namespaced_custom_object(
                group="traefik.containo.us",
                version="v1alpha1",
                namespace=self.namespace,
                plural="middlewares",
                name=f"{self.name}-redirect"
            )

            logging.info(f" ↳ [{self.namespace}/{self.name}] Middleware deleted successfully")

            logging.info(f" ↳ [{self.namespace}/{self.name}] All resources deleted successfully")
        except ApiException as e:
            logging.error(f"Error deleting resources: {e}")


class KookedDeploymentStartOperator:
    @classmethod
    def ensure_crd_exists(cls):
        dyn_client = KubernetesAPI.dynamic
        api_extensions_instance = KubernetesAPI.extensions
        crd_name = "kookeddeployments.kooked.ch"

        try:
            crd_list = api_extensions_instance.list_custom_resource_definition()
            crd_exists = any(crd.metadata.name == crd_name for crd in crd_list.items)

            if crd_exists:
                existing_crd = next(crd for crd in crd_list.items if crd.metadata.name == crd_name)
                with open("KookedDeployment-crd.yaml") as file:
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
                with open("KookedDeployment-crd.yaml") as file:
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


if __name__ == '__main__':
    sys.exit(kopf.cli.main())
