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

