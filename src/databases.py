import logging
from abc import ABC, abstractmethod
from src.KubernetesAPI import KubernetesAPI
from kubernetes.client.rest import ApiException
import random
import string


class BaseDatabase(ABC):
    def __init__(self, name, namespace):
        """
        Initialize base database deployment manager

        Args:
            name (str): Base name for resources
            namespace (str): Kubernetes namespace
        """
        self.name = name
        self.namespace = namespace

    @abstractmethod
    def create_database(self, database_name):
        """
        Create a database within the cluster
        """
        pass

    @abstractmethod
    def create_secret(self, configuration):
        """
        Create a Kubernetes secret for the database

        Args:
            configuration (dict): Database configuration
        """
        pass

    @abstractmethod
    def create_stateful_set(self, configuration):
        """
        Create a StatefulSet for the database

        Args:
            configuration (dict): Database configuration
        """
        pass

    @abstractmethod
    def create_network_policy(self):
        """
        Create a NetworkPolicy for the database
        """
        pass

    @abstractmethod
    def create_service(self):
        """
        Create a Service for the database
        """
        pass

    @abstractmethod
    def delete_database(self, configuration):
        """
        Delete a database within the cluster
        """
        pass

    @abstractmethod
    def delete_secret(self):
        """
        Delete a Kubernetes secret for the database
        """
        pass

    @abstractmethod
    def delete_stateful_set(self):
        """
        Delete a StatefulSet for the database
        """
        pass

    @abstractmethod
    def delete_network_policy(self):
        """
        Delete a NetworkPolicy for the database
        """
        pass

    @abstractmethod
    def delete_service(self):
        """
        Delete a Service for the database
        """
        pass

    def generate_random_string(self, length=12):
        """
        Generate a random string of a specific length

        Args:
            length (int): Length of the random string

        Returns:
            str: Random string
        """
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


class MongoDB(BaseDatabase):
    def __init__(self, name, namespace):
        super().__init__(name, namespace)
        self.type = "mongo"

    def create_secret(self, configuration):
        """
        Create a Kubernetes secret for MongoDB

        Args:
            configuration (dict): MongoDB configuration
        """

        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": f"{self.name}-{self.type}-secret",
                "namespace": self.namespace
            },
            "stringData": {
                "MONGODB_ROOT_USER": super().generate_random_string(),
                "MONGODB_ROOT_PASSWORD": super().generate_random_string(36),
                "MONGODB_USERNAME": configuration['user'],
                "MONGODB_PASSWORD": configuration['password'],
                "MONGODB_DATABASE": configuration['name']
            }
        }

        try:
            KubernetesAPI.core.create_namespaced_secret(
                namespace=self.namespace,
                body=secret
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] MongoDB secret created")
        except ApiException as e:
            if e.status == 409:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] Secret already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating secret: {e}")
                raise

    def create_stateful_set(self, configuration):
        """
        Create a StatefulSet for MongoDB

        Args:
            configuration (dict): MongoDB configuration
        """

        statefulset = {
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {
                "name": f"{self.name}-{self.type}",
                "namespace": self.namespace
            },
            "spec": {
                "serviceName": f"{self.name}-{self.type}",
                "replicas": 1,
                "selector": {
                    "matchLabels": {
                        "app": self.name,
                        "type": self.type
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": self.name,
                            "type": self.type
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": "mongo",
                            "image": "bitnami/mongodb:7.0.14",
                            "ports": [
                                {"containerPort": 27017}
                            ],
                            "envFrom": [
                                {
                                    "secretRef": {
                                        "name": f"{self.name}-{self.type}-secret"
                                    }
                                }
                            ],
                            "volumeMounts": [
                                {
                                    "mountPath": "/bitnami/mongodb/data/db",
                                    "name": "mongo-data"
                                }
                            ]
                        }]
                    }
                },
                "volumeClaimTemplates": [
                    {
                        "metadata": {
                            "name": "mongo-data"
                        },
                        "spec": {
                            "accessModes": ["ReadWriteMany"],
                            "storageClassName": "nfs-client",
                            "resources": {
                                "requests": {
                                    "storage": "5Gi"
                                }
                            }
                        }
                    }
                ]
            }
        }

        try:
            KubernetesAPI.apps.create_namespaced_stateful_set(
                namespace=self.namespace,
                body=statefulset
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] StatefulSet {self.name} created")
        except ApiException as e:
            if e.status == 409:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] StatefulSet already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating StatefulSet: {e}")
                raise

    def create_network_policy(self):
        """
        Create a NetworkPolicy for MongoDB
        """

        network_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"{self.name}-{self.type}",
                "namespace": self.namespace
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "app": self.name,
                        "type": self.type
                    }
                },
                "ingress": [
                    {
                        "from": [
                            {
                                "podSelector": {
                                    "matchLabels": {
                                        "app": self.name,
                                        "type": "container"
                                    }
                                }
                            }
                        ],
                        "ports": [
                            {
                                "protocol": "TCP",
                                "port": 27017
                            }
                        ]
                    }
                ],
                "policyTypes": ["Ingress"],
            }
        }

        try:
            KubernetesAPI.networking.create_namespaced_network_policy(
                namespace=self.namespace,
                body=network_policy
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] NetworkPolicy for allow access created")
        except ApiException as e:
            if e.status == 409:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] NetworkPolicy already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating NetworkPolicy: {e}")
                raise

    def create_service(self):
        """
        Create a Service for MongoDB
        """

        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": f"{self.name}-{self.type}",
                "namespace": self.namespace
            },
            "spec": {
                "selector": {
                    "app": self.name,
                    "type": self.type
                },
                "ports": [{"protocol": "TCP", "port": 27017, "targetPort": 27017}],
                "clusterIP": "None"
            }
        }

        try:
            KubernetesAPI.core.create_namespaced_service(
                namespace=self.namespace,
                body=service
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] MongoDB service created")
        except ApiException as e:
            if e.status == 409:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] Service already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating Service: {e}")
                raise

    def create_database(self, configuration):
        """
        Create a MongoDB deployment

        Args:
            configuration (dict): Database configuration
        """

        self.create_secret(configuration)
        self.create_stateful_set(configuration)
        self.create_network_policy()
        self.create_service()

    def delete_secret(self):
        """
        Delete a Kubernetes secret for MongoDB
        """

        try:
            KubernetesAPI.core.delete_namespaced_secret(
                name=f"{self.name}-{self.type}-secret",
                namespace=self.namespace
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] MongoDB secret deleted")
        except ApiException as e:
            if e.status == 404:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] Secret not found")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting secret: {e}")
                raise

    def delete_stateful_set(self):
        """
        Delete a StatefulSet for MongoDB
        """

        try:
            KubernetesAPI.apps.delete_namespaced_stateful_set(
                name=f"{self.name}-{self.type}",
                namespace=self.namespace
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] StatefulSet {self.name} deleted")
        except ApiException as e:
            if e.status == 404:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] StatefulSet not found")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting StatefulSet: {e}")
                raise

    def delete_network_policy(self):
        """
        Delete a NetworkPolicy for MongoDB
        """

        try:
            KubernetesAPI.networking.delete_namespaced_network_policy(
                name=f"{self.name}-{self.type}",
                namespace=self.namespace
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] NetworkPolicy for allow access deleted")
        except ApiException as e:
            if e.status == 404:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] NetworkPolicy not found")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting NetworkPolicy: {e}")
                raise

    def delete_service(self):
        """
        Delete a Service for MongoDB
        """

        try:
            KubernetesAPI.core.delete_namespaced_service(
                name=f"{self.name}-{self.type}",
                namespace=self.namespace
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] MongoDB service deleted")
        except ApiException as e:
            if e.status == 404:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] Service not found")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting Service: {e}")
                raise

    def delete_database(self, configuration):
        """
        Delete a database deployment

        Args:
            configuration (dict): Database configuration
        """
        self.delete_secret()
        # self.delete_stateful_set() Temporarily disabled
        self.delete_network_policy()
        self.delete_service()


class Databases:
    """
    Main orchestrator for managing database deployments
    """
    def __init__(self, name, namespace):
        """
        Initialize with database configurations

        Args:
            name (str): Base name for resources
            namespace (str): Kubernetes namespace
        """

        self.name = name
        self.namespace = namespace

    def _validate_database_configs(self, config):
        """
        Validate database configurations

        Args:
            database_configs (list): List of database configurations

        Returns:
            bool: True if all configurations are valid, False otherwise
        """

        name = config.get('name')
        if name is None:
            raise ValueError("Database name is required")
            return False

        if name.startswith('-') or name.endswith('-'):
            raise ValueError(f"Database name {name} cannot start or end with a hyphen")
            return False

        provider = config.get('provider')
        if provider is None:
            raise ValueError(f"Provider is required for database {name}")
            return False

        if provider.lower() not in ['mongodb', 'mariadb']:
            raise ValueError(f"Unsupported provider for database {name}")
            return False

        username = config.get('user')
        if username is None:
            raise ValueError(f"Username is required for database {name}")
            return False

        password = config.get('password')
        if password is None:
            raise ValueError(f"Password is required for database {name}")
            return False

    def create_database(self, configuration):
        """
        Create a database deployment

        Args:
            configuration (dict): Database configuration
        """

        logging.info(f" ↳ [{self.namespace}/{self.name}] Creating database resources for {configuration['name']}")

        self._validate_database_configs(configuration)

        if configuration['provider'].lower() == 'mongodb':
            manager = MongoDB(self.name, self.namespace)
            manager.create_database(configuration)

        # elif configuration['provider'].lower() == 'mariadb':
        #     manager = MariaDB(self.name, self.namespace)
        #     manager.create_database_cluster()

        #     db = f"{self.name}-{configuration['db']}"

        #     manager.create_database(db)
        #     manager.create_user(configuration['user'], configuration['password'], db)
        else:
            raise ValueError(f"Unsupported database provider: {configuration['provider']}")

    def delete_database(self, configuration):
        """
        Delete a database deployment

        Args:
            configuration (dict): Database configuration
        """

        logging.info(f" ↳ [{self.namespace}/{self.name}] Deleting database resources for {configuration['name']}")

        self._validate_database_configs(configuration)

        if configuration['provider'].lower() == 'mongodb':
            manager = MongoDB(self.name, self.namespace)
            manager.delete_database(configuration)

            # Ajoutez votre logique de suppression ici
        elif configuration['provider'].lower() == 'mariadb':
            manager = MariaDB(self.name, self.namespace)
            # Ajoutez votre logique de suppression ici
        else:
            raise ValueError(f"Unsupported database provider: {configuration['provider']}")
