# Kopf documentation : https://kopf.readthedocs.io/
#
# Run with `python3 kooked-kopf.py run -A`
#
import argparse
import kopf
import kopf.cli
import logging
from kubernetes import client, config
from kubernetes.dynamic import DynamicClient
from kubernetes.client.exceptions import ApiException
import base64
import os
import subprocess
import sys
import yaml
import re
from datetime import datetime, timezone
import time


@kopf.on.delete('kooked.ch', 'v1', 'kookeddeployments')
def on_delete_kookeddeployment(spec, name, namespace, **kwargs):
    KookedDeploymentOperator(name, namespace, spec).delete_kookeddeployment(spec)

@kopf.on.startup()
def on_kopf_startup (**kwargs):
    KookedDeploymentStartOperator.ensure_crd_exists()
    KookedDeploymentStartOperator.create_cluster_issuer()
    KookedDeploymentStartOperator.ensure_traefik_rbac()


@kopf.on.create('kooked.ch', 'v1', 'kookeddeployments')
def on_create_kookeddeployment(spec, name, namespace, **kwargs):
    KookedDeploymentOperator(name, namespace, spec).create_kookeddeployment(spec)


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


    def create_service(self, container_spec):
        logging.info(f" ↳ [{self.namespace}/{self.name}] Creating service")

        service_ports = []
        for domain in container_spec.get('domains', []):
            service_ports.append(
                client.V1ServicePort(
                    port=80,
                    target_port=domain.get('port', 80),
                    protocol="TCP"
                )
            )

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
                "name": self.name,
                "namespace": self.namespace
            },
            "spec": {
                "dnsNames": [domain],
                "issuerRef": {
                    "name": "letsencrypt-prod",
                    "kind": "ClusterIssuer"
                },
                "secretName": f"{self.name}-tls",
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


