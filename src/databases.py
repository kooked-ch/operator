import logging
import random
import string
import abc
from typing import Dict, Any

from kubernetes.client.rest import ApiException
from src.KubernetesAPI import KubernetesAPI


class DatabaseConfig:
    """
    Configuration class for database deployment settings
    """
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize database configuration with validation

        Args:
            config (Dict[str, Any]): Configuration dictionary
        """
        self._validate_config(config)
        self.name = config['name']
        self.provider = config['provider']
        self.user = config['user']
        self.password = config['password']

    def _validate_config(self, config: Dict[str, Any]):
        """
        Validate database configuration

        Raises:
            ValueError: If configuration is invalid
        """
        required_keys = ['name', 'provider', 'user', 'password']
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Missing required configuration key: {key}")

        if config['name'].startswith('-') or config['name'].endswith('-'):
            raise ValueError(f"Database name {config['name']} cannot start or end with a hyphen")

        if config['provider'].lower() not in ['mongodb', 'mariadb']:
            raise ValueError(f"Unsupported provider: {config['provider']}")


class BaseDatabase(abc.ABC):
    """
    Abstract base class for database deployments in Kubernetes
    """
    def __init__(self, name: str, namespace: str, config: DatabaseConfig):
        """
        Initialize base database deployment

        Args:
            name (str): Base name for resources
            namespace (str): Kubernetes namespace
            config (DatabaseConfig): Database configuration
        """
        self.name = name
        self.namespace = namespace
        self.config = config
        self.type = self._get_type()

    @abc.abstractmethod
    def _get_type(self) -> str:
        """
        Get database type identifier

        Returns:
            str: Database type
        """
        pass

    @abc.abstractmethod
    def _get_port(self) -> int:
        """
        Get database service port

        Returns:
            int: Service port number
        """
        pass

    @abc.abstractmethod
    def _get_image(self) -> str:
        """
        Get database container image

        Returns:
            str: Container image name and tag
        """
        pass

    @abc.abstractmethod
    def _get_volume_mount_path(self) -> str:
        """
        Get volume mount path in container

        Returns:
            str: Volume mount path
        """
        pass

    @staticmethod
    def generate_random_string(length: int = 12) -> str:
        """
        Generate a random alphanumeric string

        Args:
            length (int, optional): String length. Defaults to 12.

        Returns:
            str: Random string
        """
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def _create_kubernetes_resource(self, resource_type: str, body: Dict[str, Any]):
        """
        Generic method to create Kubernetes resources

        Args:
            resource_type (str): Resource type (e.g., 'secret', 'service')
            body (Dict[str, Any]): Resource configuration
        """
        api_methods = {
            'secret': KubernetesAPI.core.create_namespaced_secret,
            'service': KubernetesAPI.core.create_namespaced_service,
            'network_policy': KubernetesAPI.networking.create_namespaced_network_policy,
            'stateful_set': KubernetesAPI.apps.create_namespaced_stateful_set
        }

        try:
            api_methods[resource_type](namespace=self.namespace, body=body)
            logging.info(f"    ↳ [{self.namespace}/{self.name}] {resource_type.replace('_', ' ').title()} created")
        except ApiException as e:
            if e.status == 409:
                logging.warning(f"    ↳ [{self.namespace}/{self.name}] {resource_type.replace('_', ' ').title()} already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating {resource_type}: {e}")
                raise

    def _delete_kubernetes_resource(self, resource_type: str, name: str):
        """
        Generic method to delete Kubernetes resources

        Args:
            resource_type (str): Resource type
            name (str): Resource name
        """
        api_methods = {
            'secret': KubernetesAPI.core.delete_namespaced_secret,
            'service': KubernetesAPI.core.delete_namespaced_service,
            'network_policy': KubernetesAPI.networking.delete_namespaced_network_policy,
            'stateful_set': KubernetesAPI.apps.delete_namespaced_stateful_set
        }

        try:
            api_methods[resource_type](name=name, namespace=self.namespace)
            logging.info(f"    ↳ [{self.namespace}/{self.name}] {resource_type.replace('_', ' ').title()} deleted")
        except ApiException as e:
            if e.status == 404:
                logging.warning(f"    ↳ [{self.namespace}/{self.name}] {resource_type.replace('_', ' ').title()} not found")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error deleting {resource_type}: {e}")

    def create_secret(self):
        """Create Kubernetes secret for the database"""
        raise NotImplementedError

    def create_stateful_set(self):
        """Create StatefulSet for the database"""
        raise NotImplementedError

    def create_network_policy(self):
        """Create NetworkPolicy for the database"""
        raise NotImplementedError

    def create_service(self):
        """Create Service for the database"""
        raise NotImplementedError

    def delete_secret(self):
        """Delete Kubernetes secret"""
        raise NotImplementedError

    def delete_stateful_set(self):
        """Delete StatefulSet"""
        raise NotImplementedError

    def delete_network_policy(self):
        """Delete NetworkPolicy"""
        raise NotImplementedError

    def delete_service(self):
        """Delete Service"""
        raise NotImplementedError

    def create_database(self):
        """
        Create complete database deployment
        """
        self.create_secret()
        self.create_stateful_set()
        self.create_network_policy()
        self.create_service()

    def delete_database(self):
        """
        Delete complete database deployment
        """
        self.delete_secret()
        self.delete_stateful_set()
        self.delete_network_policy()
        self.delete_service()


class MariaDB(BaseDatabase):
    def _get_type(self) -> str:
        return "mariadb"

    def _get_port(self) -> int:
        return 3306

    def _get_image(self) -> str:
        return "bitnami/mariadb:11.4.4"

    def _get_volume_mount_path(self) -> str:
        return "/bitnami/mariadb"

    def create_secret(self):
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": f"{self.name}-{self.type}-secret",
                "namespace": self.namespace
            },
            "stringData": {
                "MARIADB_ROOT_PASSWORD": self.generate_random_string(64),
                "MARIADB_USER": self.config.user,
                "MARIADB_PASSWORD": self.config.password,
                "MARIADB_DATABASE": self.config.name,
                "MARIADB_CHARACTER_SET": "utf8mb4",
                "MARIADB_COLLATE": "utf8mb4_unicode_ci"
            }
        }
        self._create_kubernetes_resource('secret', secret)

    def create_stateful_set(self):
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
                            "name": "mariadb",
                            "image": self._get_image(),
                            "ports": [{"containerPort": self._get_port()}],
                            "envFrom": [{"secretRef": {"name": f"{self.name}-{self.type}-secret"}}],
                            "volumeMounts": [{"mountPath": self._get_volume_mount_path(), "name": "mariadb-data"}]
                        }]
                    }
                },
                "volumeClaimTemplates": [{
                    "metadata": {"name": "mariadb-data"},
                    "spec": {
                        "accessModes": ["ReadWriteMany"],
                        "storageClassName": "nfs-client",
                        "resources": {"requests": {"storage": "5Gi"}}
                    }
                }]
            }
        }
        self._create_kubernetes_resource('stateful_set', statefulset)

    def create_network_policy(self):
        network_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"{self.name}-{self.type}",
                "namespace": self.namespace
            },
            "spec": {
                "podSelector": {"matchLabels": {"app": self.name, "type": self.type}},
                "ingress": [{
                    "from": [{"podSelector": {"matchLabels": {"app": self.name, "type": "container"}}}],
                    "ports": [{"protocol": "TCP", "port": self._get_port()}]
                }],
                "policyTypes": ["Ingress"]
            }
        }
        self._create_kubernetes_resource('network_policy', network_policy)

    def create_service(self):
        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": f"{self.name}-{self.type}",
                "namespace": self.namespace
            },
            "spec": {
                "selector": {"app": self.name, "type": self.type},
                "ports": [{"protocol": "TCP", "port": self._get_port(), "targetPort": self._get_port()}],
                "clusterIP": "None"
            }
        }
        self._create_kubernetes_resource('service', service)

    def delete_secret(self):
        self._delete_kubernetes_resource('secret', f"{self.name}-{self.type}-secret")

    def delete_stateful_set(self):
        self._delete_kubernetes_resource('stateful_set', f"{self.name}-{self.type}")

    def delete_network_policy(self):
        self._delete_kubernetes_resource('network_policy', f"{self.name}-{self.type}")

    def delete_service(self):
        self._delete_kubernetes_resource('service', f"{self.name}-{self.type}")


class PostgreSQL(BaseDatabase):
    def _get_type(self) -> str:
        return "postgres"

    def _get_port(self) -> int:
        return 5432

    def _get_image(self) -> str:
        return "postgres:15.3"

    def _get_volume_mount_path(self) -> str:
        return "/var/lib/postgresql/data"

    def create_secret(self):
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": f"{self.name}-{self.type}-secret",
                "namespace": self.namespace
            },
            "stringData": {
                "POSTGRES_USER": self.config.user,
                "POSTGRES_PASSWORD": self.config.password,
                "POSTGRES_DB": self.config.name
            }
        }
        self._create_kubernetes_resource('secret', secret)

    def create_stateful_set(self):
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
                            "name": "postgres",
                            "image": self._get_image(),
                            "ports": [{"containerPort": self._get_port()}],
                            "envFrom": [{"secretRef": {"name": f"{self.name}-{self.type}-secret"}}],
                            "volumeMounts": [{"mountPath": self._get_volume_mount_path(), "name": "postgres-data"}]
                        }]
                    }
                },
                "volumeClaimTemplates": [{
                    "metadata": {"name": "postgres-data"},
                    "spec": {
                        "accessModes": ["ReadWriteMany"],
                        "storageClassName": "nfs-client",
                        "resources": {"requests": {"storage": "5Gi"}}
                    }
                }]
            }
        }
        self._create_kubernetes_resource('stateful_set', statefulset)

    def create_network_policy(self):
        network_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"{self.name}-{self.type}",
                "namespace": self.namespace
            },
            "spec": {
                "podSelector": {"matchLabels": {"app": self.name, "type": self.type}},
                "ingress": [{
                    "from": [{"podSelector": {"matchLabels": {"app": self.name, "type": "container"}}}],
                    "ports": [{"protocol": "TCP", "port": self._get_port()}]
                }],
                "policyTypes": ["Ingress"]
            }
        }
        self._create_kubernetes_resource('network_policy', network_policy)

    def create_service(self):
        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": f"{self.name}-{self.type}",
                "namespace": self.namespace
            },
            "spec": {
                "selector": {"app": self.name, "type": self.type},
                "ports": [{"protocol": "TCP", "port": self._get_port(), "targetPort": self._get_port()}],
                "clusterIP": "None"
            }
        }
        self._create_kubernetes_resource('service', service)

    def delete_secret(self):
        self._delete_kubernetes_resource('secret', f"{self.name}-{self.type}-secret")

    def delete_stateful_set(self):
        self._delete_kubernetes_resource('stateful_set', f"{self.name}-{self.type}")

    def delete_network_policy(self):
        self._delete_kubernetes_resource('network_policy', f"{self.name}-{self.type}")

    def delete_service(self):
        self._delete_kubernetes_resource('service', f"{self.name}-{self.type}")


class MongoDB(BaseDatabase):
    def _get_type(self) -> str:
        return "mongodb"

    def _get_port(self) -> int:
        return 27017

    def _get_image(self) -> str:
        return "bitnami/mongodb:7.0.14"

    def _get_volume_mount_path(self) -> str:
        return "/bitnami/mongodb/data/db"

    def create_secret(self):
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": f"{self.name}-{self.type}-secret",
                "namespace": self.namespace
            },
            "stringData": {
                "MONGODB_ROOT_USER": self.generate_random_string(),
                "MONGODB_ROOT_PASSWORD": self.generate_random_string(36),
                "MONGODB_USERNAME": self.config.user,
                "MONGODB_PASSWORD": self.config.password,
                "MONGODB_DATABASE": self.config.name
            }
        }
        self._create_kubernetes_resource('secret', secret)

    def create_stateful_set(self):
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
                            "name": "mongodb",
                            "image": self._get_image(),
                            "ports": [{"containerPort": self._get_port()}],
                            "envFrom": [{"secretRef": {"name": f"{self.name}-{self.type}-secret"}}],
                            "volumeMounts": [{"mountPath": self._get_volume_mount_path(), "name": "mongodb-data"}]
                        }]
                    }
                },
                "volumeClaimTemplates": [{
                    "metadata": {"name": "mongodb-data"},
                    "spec": {
                        "accessModes": ["ReadWriteMany"],
                        "storageClassName": "nfs-client",
                        "resources": {"requests": {"storage": "5Gi"}}
                    }
                }]
            }
        }
        self._create_kubernetes_resource('stateful_set', statefulset)

    def create_network_policy(self):
        network_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"{self.name}-{self.type}",
                "namespace": self.namespace
            },
            "spec": {
                "podSelector": {"matchLabels": {"app": self.name, "type": self.type}},
                "ingress": [{
                    "from": [{"podSelector": {"matchLabels": {"app": self.name, "type": "container"}}}],
                    "ports": [{"protocol": "TCP", "port": self._get_port()}]
                }],
                "policyTypes": ["Ingress"]
            }
        }
        self._create_kubernetes_resource('network_policy', network_policy)

    def create_service(self):
        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": f"{self.name}-{self.type}",
                "namespace": self.namespace
            },
            "spec": {
                "selector": {"app": self.name, "type": self.type},
                "ports": [{"protocol": "TCP", "port": self._get_port(), "targetPort": self._get_port()}],
                "clusterIP": "None"
            }
        }
        self._create_kubernetes_resource('service', service)

    def delete_secret(self):
        self._delete_kubernetes_resource('secret', f"{self.name}-{self.type}-secret")

    def delete_stateful_set(self):
        self._delete_kubernetes_resource('stateful_set', f"{self.name}-{self.type}")

    def delete_network_policy(self):
        self._delete_kubernetes_resource('network_policy', f"{self.name}-{self.type}")

    def delete_service(self):
        self._delete_kubernetes_resource('service', f"{self.name}-{self.type}")


class Databases:
    """
    Main orchestrator for managing database deployments
    """
    def __init__(self, name: str, namespace: str):
        """
        Initialize database manager

        Args:
            name (str): Base name for resources
            namespace (str): Kubernetes namespace
        """
        self.name = name
        self.namespace = namespace

    def create_database(self, config: Dict[str, Any]):
        """
        Create a database deployment

        Args:
            config (Dict[str, Any]): Database configuration
        """
        logging.info(f" ↳ [{self.namespace}/{self.name}] Creating database resources for {config['name']}")

        db_config = DatabaseConfig(config)

        if db_config.provider.lower() == 'mongodb':
            database = MongoDB(self.name, self.namespace, db_config)
        elif db_config.provider.lower() == 'mariadb':
            database = MariaDB(self.name, self.namespace, db_config)
        elif db_config.provider.lower() == 'postgresql':
            database = PostgreSQL(self.name, self.namespace, db_config)
        else:
            raise ValueError(f"Unsupported database provider: {db_config.provider}")

        database.create_database()

    def delete_database(self, config: Dict[str, Any]):
        """
        Delete a database deployment

        Args:
            config (Dict[str, Any]): Database configuration
        """
        logging.info(f" ↳ [{self.namespace}/{self.name}] Deleting database resources for {config['name']}")

        db_config = DatabaseConfig(config)

        if db_config.provider.lower() == 'mongodb':
            database = MongoDB(self.name, self.namespace, db_config)
        elif db_config.provider.lower() == 'mariadb':
            database = MariaDB(self.name, self.namespace, db_config)
        elif db_config.provider.lower() == 'postgresql':
            database = PostgreSQL(self.name, self.namespace, db_config)
        else:
            raise ValueError(f"Unsupported database provider: {db_config.provider}")

        database.delete_database()
