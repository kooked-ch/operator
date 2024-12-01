from setuptools import setup, find_packages

setup(
    name='kooked-kopf',
    version='3.0.0',
    description='Kopf operator for managing and deploying Kooked applications',
    url='https://github.com/kooked-ch/operator',
    packages=find_packages(),
    install_requires=[
        'kopf==1.37.2',
        'kubernetes==31.0.0',
        "requests==2.26.0",
    ],
)
