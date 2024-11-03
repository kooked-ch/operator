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

