import logging
from abc import ABC, abstractmethod
from src.KubernetesAPI import KubernetesAPI
from kubernetes.client.rest import ApiException


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
    def create_user(self, username, password, database_name, roles=None):
        """
        Create a database user with specific permissions
        """
        pass


class MongoDB(BaseDatabase):
    """
    Specialized manager for MongoDB deployments using MongoDB Community Operator
    """

    def create_service_account(self):
        """
        Create a service account for the MongoDB operator
        """
        service_account = {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "mongodb-database",
                "namespace": self.namespace
            }
        }

        try:
            KubernetesAPI.core.create_namespaced_service_account(
                namespace=self.namespace,
                body=service_account
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Service account created")
        except ApiException as e:
            if e.status == 409:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] Service account already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating service account: {e}")
                raise
        except Exception as e:
            logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating service account: {e}")
            raise

    def create_role(self):
        """
        Create a role for the MongoDB operator
        """
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {
                "name": "mongodb-database",
                "namespace": self.namespace
            },
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["secrets"],
                    "verbs": ["get"]
                },
                {
                    "apiGroups": [""],
                    "resources": ["pods"],
                    "verbs": ["patch", "delete", "get"]
                }
            ]
        }

        try:
            KubernetesAPI.rbac.create_namespaced_role(
                namespace=self.namespace,
                body=role
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Role created")
        except ApiException as e:
            if e.status == 409:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] Role already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating role: {e}")
                raise
        except Exception as e:
            logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating role: {e}")
            raise

    def create_role_binding(self):
        """
        Create a role binding for the MongoDB operator
        """
        role_binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {
                "name": "mongodb-database",
                "namespace": self.namespace
            },
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "mongodb-database"
            },
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": "mongodb-database",
                    "namespace": self.namespace
                }
            ]
        }

        try:
            KubernetesAPI.rbac.create_namespaced_role_binding(
                namespace=self.namespace,
                body=role_binding
            )
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Role binding created")
        except ApiException as e:
            if e.status == 409:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] Role binding already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating role binding: {e}")
                raise
        except Exception as e:
            logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating role binding: {e}")
            raise

    def create_user(self, password):
        """
        Create a user with specific rights in the MongoDB cluster

        Args:
            password (str): Password
        """
        try:
            secret_name = f"{self.name}-mongo-password"

            # Create password secret
            secret = {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": secret_name,
                    "namespace": self.namespace,
                },
                "type": "Opaque",
                "stringData": {
                    "password": password
                }
            }

            KubernetesAPI.core.create_namespaced_secret(
                namespace=self.namespace,
                body=secret
            )

            logging.info(f"    ↳ [{self.namespace}/{self.name}] User secret created: {secret_name}")
        except ApiException as e:
            if e.status == 409:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] Secret {secret_name} already exists")
                KubernetesAPI.core.replace_namespaced_secret(
                    name=secret_name,
                    namespace=self.namespace,
                    body=secret
                )
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating user secret: {e}")
                raise

        except Exception as e:
            logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating user secret: {e}")
            raise

    def create_database(self, configuration):
        """
        Create a database within the MongoDB cluster.
        Note: In MongoDB, database creation happens automatically on first use.

        Args:
            configuration (dict): Database configuration
        """
        try:
            logging.info(f"    ↳ [{self.namespace}/{self.name}] Creating MongoDB cluster {self.name}")

            mongo = {
                "apiVersion": "mongodbcommunity.mongodb.com/v1",
                "kind": "MongoDBCommunity",
                "metadata": {
                    "name": f"{self.name}-mongo",
                    "namespace": self.namespace
                },
                "spec": {
                    "members": 1,
                    "version": "8.0.3",
                    "type": "ReplicaSet",
                    "security": {
                        "authentication": {
                            "modes": ["SCRAM-SHA-256", "SCRAM-SHA-1"]
                        }
                    },
                    "users": [
                        {
                            "name": configuration['user'],
                            "db": configuration['name'],
                            "passwordSecretRef": {
                                "name": f"{self.name}-mongo-password"
                            },
                            "roles": [
                                {"name": "readWrite", "db": configuration['name']}
                            ],
                            "scramCredentialsSecretName": f"{self.name}-mongo"
                        }
                    ],
                    "additionalMongodConfig": {
                        "storage": {
                            "wiredTiger": {
                                "engineConfig": {
                                    "journalCompressor": "zlib"
                                }
                            }
                        }
                    }
                }
            }

            KubernetesAPI.custom.create_namespaced_custom_object(
                group="mongodbcommunity.mongodb.com",
                version="v1",
                namespace=self.namespace,
                plural="mongodbcommunity",
                body=mongo
            )

            logging.info(f"    ↳ [{self.namespace}/{self.name}] MongoDB {self.name} created")
        except ApiException as e:
            if e.status == 409:
                logging.warn(f"    ↳ [{self.namespace}/{self.name}] MongoDB cluster {self.name} already exists")
            else:
                logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating MongoDB cluster: {e}")
                raise
        except Exception as e:
            logging.error(f"    ↳ [{self.namespace}/{self.name}] Error creating MongoDB cluster: {e}")
            raise


class MariaDB(BaseDatabase):
    """
    Specialized manager for MariaDB deployments using MariaDB Operator
    """
    def _check_cluster_exists(self):
        """
        Verify if a MariaDB resource exists in the namespace

        Returns:
            bool: True if MariaDB resource exists, False otherwise
        """
        try:
            mariadb_resources = KubernetesAPI.custom.list_namespaced_custom_resource(
                group="mariadb.mmontes.io",
                version="v1alpha1",
                namespace=self.namespace,
                plural="mariadbs"
            )
            return len(mariadb_resources.items) > 0
        except Exception as e:
            logging.error(f"Error checking MariaDB resources: {e}")
            return False

    def create_database_cluster(self, replicas=3, version="10.11.2"):
        """
        Create a MariaDB cluster if it doesn't exist

        Args:
            replicas (int): Number of replicas
            version (str): MariaDB version
        """
        if self._check_database_exists():
            logging.info("MariaDB cluster already exists")
            return

        mariadb_cluster = {
            "apiVersion": "mariadb.mmontes.io/v1alpha1",
            "kind": "MariaDB",
            "metadata": {
                "name": self.name,
                "namespace": self.namespace
            },
            "spec": {
                "replicas": replicas,
                "mariadbVersion": version,
                "primaryUpdateStrategy": "RollingUpdate",
                "primary": {},
                "secondary": {}
            }
        }

        try:
            KubernetesAPI.custom.create_namespaced_custom_resource(
                group="mariadb.mmontes.io",
                version="v1alpha1",
                namespace=self.namespace,
                plural="mariadbs",
                body=mariadb_cluster
            )
            logging.info(f"MariaDB cluster {self.name} created with {replicas} replicas")
        except Exception as e:
            logging.error(f"Error creating MariaDB cluster: {e}")
            raise

    def create_database(self, database_name):
        """
        Create a database within the MariaDB cluster

        Args:
            database_name (str): Name of the database
        """
        database_resource = {
            "apiVersion": "mariadb.mmontes.io/v1alpha1",
            "kind": "Database",
            "metadata": {
                "name": f"{self.name}-mongo",
                "namespace": self.namespace
            },
            "spec": {
                "mariaDbRef": {
                    "name": self.name
                },
                "characterSet": "utf8mb4",
                "collate": "utf8mb4_unicode_ci",
                "database": database_name
            }
        }

        try:
            KubernetesAPI.custom.create_namespaced_custom_resource(
                group="mariadb.mmontes.io",
                version="v1alpha1",
                namespace=self.namespace,
                plural="databases",
                body=database_resource
            )
            logging.info(f"Database {database_name} created")
        except Exception as e:
            logging.error(f"Error creating database: {e}")
            raise

    def create_user(self, username, password, database_name, roles=None):
        """
        Create a database user with specific permissions

        Args:
            username (str): Username
            password (str): Password
            database_name (str): Target database
            roles (list, optional): List of roles. Default is ALL PRIVILEGES
        """
        secret_name = f"{self.name}-{username}-password"
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": secret_name,
                "namespace": self.namespace
            },
            "type": "Opaque",
            "stringData": {
                "password": password
            }
        }

        try:
            KubernetesAPI.core.create_namespaced_secret(
                namespace=self.namespace,
                body=secret
            )

            if roles is None:
                roles = [{"privileges": "ALL PRIVILEGES", "database": database_name}]

            user_resource = {
                "apiVersion": "mariadb.mmontes.io/v1alpha1",
                "kind": "User",
                "metadata": {
                    "name": f"{self.name}-{username}",
                    "namespace": self.namespace
                },
                "spec": {
                    "mariaDbRef": {
                        "name": self.name
                    },
                    "username": username,
                    "passwordSecretKeyRef": {
                        "name": secret_name,
                        "key": "password"
                    },
                    "grants": [
                        f"{role['privileges']} ON {role['database']}.* TO '{username}'@'%'" 
                        for role in roles
                    ]
                }
            }

            KubernetesAPI.custom.create_namespaced_custom_resource(
                group="mariadb.mmontes.io",
                version="v1alpha1",
                namespace=self.namespace,
                plural="users",
                body=user_resource
            )
            logging.info(f"User {username} created successfully")

        except Exception as e:
            logging.error(f"Error creating user: {e}")
            raise


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

            manager.create_service_account()
            manager.create_role()
            manager.create_role_binding()

            manager.create_user(configuration['password'])
            manager.create_database(configuration)
        elif configuration['provider'].lower() == 'mariadb':
            manager = MariaDB(self.name, self.namespace)
            manager.create_database_cluster()

            db = f"{self.name}-{configuration['db']}"

            manager.create_database(db)
            manager.create_user(configuration['user'], configuration['password'], db)
        else:
            raise ValueError(f"Unsupported database provider: {configuration['provider']}")


# Example Usage
def main():
    database_configs = [
        {
            'settings': {
                'db': 'markdown_to_pdf',
                'user': 'asdhajdskasd',
                'password': 'asdhasdhasd'
            }
        },
        {
            'name': 'mariadb',
            'namespace': 'default',
            'settings': {
                'db': 'markdown_to_pdf',
                'user': 'asdhajdskasd',
                'password': 'asdhasdhasd'
            }
        }
    ]

    try:
        orchestrator = DatabaseDeploymentOrchestrator(database_configs)
        
        # Optional: Access specific database managers if needed
        mongo_manager = orchestrator.get_database_manager('mongo')
        mariadb_manager = orchestrator.get_database_manager('mariadb')

    except Exception as e:
        logging.error(f"Database deployment orchestration failed: {e}")

if __name__ == "__main__":
    main()
