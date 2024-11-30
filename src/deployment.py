import logging
import re
from kubernetes import client
from kubernetes.client.exceptions import ApiException
from src.KubernetesAPI import KubernetesAPI


class Deployment:
    def __init__(self, name, namespace):
        """
        Initialize deployment instance with namespace and resource name.

        Args:
            name (str): Resource name
            namespace (str): Kubernetes namespace
        """
        self.name = name
        self.namespace = namespace

    def validate_containers(self, containers):
        """
        Validate multiple container configurations.

        Args:
            containers (list): List of container configurations

        Raises:
            ValueError: If container configurations are invalid
        """
        if not containers or not isinstance(containers, list):
            raise ValueError("Containers must be a non-empty list")

        validated_containers = []
        container_names = set()

        for container in containers:
            if not isinstance(container, dict):
                raise ValueError("Each container must be a dictionary")

            required_keys = ['name', 'image']
            for key in required_keys:
                if key not in container:
                    raise ValueError(f"Missing required container configuration key: {key}")

            if container['name'] in container_names:
                raise ValueError(f"Duplicate container name: {container['name']}")
            container_names.add(container['name'])

            if not re.match(r'^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[a-zA-Z0-9.-]+$', container['image']):
                raise ValueError(f"Invalid image format: {container['image']}")

            if 'env' in container:
                if not isinstance(container['env'], list):
                    raise ValueError("Environment variables must be a list")
                for env_var in container['env']:
                    if not isinstance(env_var, dict) or 'name' not in env_var or 'value' not in env_var:
                        raise ValueError("Each environment variable must be a dictionary with 'name' and 'value'")

            if 'volumes' in container:
                if not isinstance(container['volumes'], list):
                    raise ValueError("Volumes must be a list")
                for volume in container['volumes']:
                    if not isinstance(volume, dict) or 'name' not in volume or 'mountPath' not in volume:
                        raise ValueError("Each volume must be a dictionary with 'name' and 'mountPath'")

            validated_containers.append(container)

        return validated_containers

    def create_pvc(self, volume_name, storage_size, storage_class='nfs-client'):
        """
        Create a Persistent Volume Claim (PVC) for a container.

        Args:
            volume_name (str): Name of the volume
            storage_size (str): Storage size (e.g., '5Gi')
            storage_class (str, optional): Storage class name. Defaults to 'nfs-client'.

        Returns:
            bool: True if PVC creation successful, False otherwise
        """
        pvc = {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": volume_name,
                "namespace": self.namespace,
                "labels": {
                    "app": self.name
                }
            },
            "spec": {
                "accessModes": ["ReadWriteMany"],
                "storageClassName": storage_class,
                "resources": {
                    "requests": {
                        "storage": storage_size
                    }
                }
            }
        }

        try:
            KubernetesAPI.core.create_namespaced_persistent_volume_claim(
                namespace=self.namespace,
                body=pvc
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Created PVC {volume_name} with {storage_size} storage")

        except ApiException as e:
            if e.status == 409:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] PVC {volume_name} already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating PVC: {e}")
                raise ValueError(f"Error creating PVC {volume_name}")

    def create_deployment(self, containers):
        """
        Create Kubernetes Deployments for multiple containers.

        Args:
            containers (list): List of container configurations

        Returns:
            bool: True if deployment creation successful, False otherwise
        """
        try:

            logging.info(f" ↳ [{self.namespace}/{self.name}] Creating deployment")

            validated_containers = self.validate_containers(containers)

            container_specs = []
            volumes = []
            volumes_names = []

            for container in validated_containers:
                for volume in container.get('volumes', []):
                    if volume['name'] not in volumes_names:
                        self.create_pvc(f"{self.name}-{volume['name']}", '5Gi')
                        volumes_names.append(volume['name'])
                        volumes.append(client.V1Volume(
                            name=f"{self.name}-{volume['name']}",
                            persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                claim_name=f"{self.name}-{volume['name']}"
                            )
                        ))

            for container in validated_containers:
                container_spec = client.V1Container(
                    name=container['name'],
                    image=container['image'],
                    env=[
                        client.V1EnvVar(name=env['name'], value=env['value'])
                        for env in container.get('env', [])
                    ],
                    ports=[
                        client.V1ContainerPort(container_port=int(port))
                        for port in container.get('ports', [])
                    ],
                    volume_mounts=[
                        client.V1VolumeMount(
                            name=f"{self.name}-{volume['name']}",
                            mount_path=volume['mountPath']
                        )
                        for volume in container.get('volumes', [])
                    ],
                    resources=client.V1ResourceRequirements(
                        requests={
                            "cpu": "100m",
                            "memory": "128Mi"
                        },
                        limits={
                            "cpu": "500m",
                            "memory": "512Mi"
                        }
                    )
                )
                container_specs.append(container_spec)

            deployment = client.V1Deployment(
                api_version="apps/v1",
                kind="Deployment",
                metadata=client.V1ObjectMeta(
                    name=self.name,
                    namespace=self.namespace,
                    labels={"app": self.name}
                ),
                spec=client.V1DeploymentSpec(
                    replicas=1,
                    selector=client.V1LabelSelector(
                        match_labels={"app": self.name}
                    ),
                    template=client.V1PodTemplateSpec(
                        metadata=client.V1ObjectMeta(
                            labels={"app": self.name}
                        ),
                        spec=client.V1PodSpec(
                            containers=container_specs,
                            volumes=volumes
                        )
                    )
                )
            )

            KubernetesAPI.apps.create_namespaced_deployment(
                namespace=self.namespace,
                body=deployment
            )

            logging.info(f"    ↳ [{self.namespace}/{self.name}] Created deployment with {len(validated_containers)} containers")

        except Exception as e:
            logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating deployment: {e}", exc_info=True)
            raise ValueError("Error creating deployment")

    def delete_deployment(self):
        """
        Delete the Kubernetes Deployment and associated resources.

        Returns:
            bool: True if deletion successful, False otherwise
        """
        try:
            logging.info(f" ↳ [{self.namespace}/{self.name}] Delete deployment resources")

            KubernetesAPI.apps.delete_namespaced_deployment(
                name=self.name,
                namespace=self.namespace
            )

            logging.info(f"    ↳ [{self.namespace}/{self.name}] Deleted deployment")

            pvcs = KubernetesAPI.core.list_namespaced_persistent_volume_claim(
                namespace=self.namespace,
                label_selector=f"app={self.name}"
            )

            for pvc in pvcs.items:
                KubernetesAPI.core.delete_namespaced_persistent_volume_claim(
                    name=pvc.metadata.name,
                    namespace=self.namespace
                )
                logging.info(f"    ↳ [{self.namespace}/{self.name}] Deleted PVC {pvc.metadata.name}")

        except ApiException as e:
            if e.status == 404:
                logging.info(f"    ↳ [{self.namespace}/{self.name}] Deployment or resources not found")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting deployment: {e}")
                raise ValueError("Error deleting deployment")

        logging.info(f"    ↳ [{self.namespace}/{self.name}] All deployment resources deleted successfully")
