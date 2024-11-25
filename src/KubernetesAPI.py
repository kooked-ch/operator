from src.classproperty import classproperty
from kubernetes import client, config
from kubernetes.dynamic import DynamicClient
import os


class KubernetesAPI:
    __singleton = None

    @classmethod
    def __get(cls):
        if cls.__singleton is None:
            cls.__singleton = cls()

        return cls.__singleton

    def __init__(self):

        if os.path.exists(
                '/var/run/secrets/kubernetes.io/serviceaccount/token'):
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
