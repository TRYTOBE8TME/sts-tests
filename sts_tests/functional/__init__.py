import boto3
from botocore import UNSIGNED
from botocore.client import Config
from botocore.exceptions import ClientError
from botocore.handlers import disable_signing
import configparser
import os
import munch
import random
import string
import itertools

config = munch.Munch

def setup():
    cfg = configparser.RawConfigParser()
    try:
        path = os.environ['STSTEST_CONF']
    except KeyError:
        raise RuntimeError(
            'To run tests, point environment '
            + 'variable STSTEST_CONF to a config file.',
            )
    cfg.read(path)

    if not cfg.defaults():
        raise RuntimeError('Your config file is missing the DEFAULT section!')
    if not cfg.has_section("sts"):
        raise RuntimeError('Your config file is missing the "sts" section!')
    if not cfg.has_section("iam"):
        raise RuntimeError('Your config file is missing the "iam" section!')
    if not cfg.has_section("s3 main"):
        raise RuntimeError('Your config file is missing the "s3 main" section!')

    global prefix

    defaults = cfg.defaults()

    # vars from the DEFAULT section
    config.default_host = defaults.get("host")
    config.default_port = int(defaults.get("port"))
    config.default_is_secure = cfg.getboolean('DEFAULT', "is_secure")

    proto = 'https' if config.default_is_secure else 'http'
    config.default_endpoint = "%s://%s:%d" % (proto, config.default_host, config.default_port)

    # vars from the main section
    config.sts_access_key = cfg.get('sts',"access_key")
    config.sts_secret_key = cfg.get('sts',"secret_key")
    config.sts_display_name = cfg.get('sts',"display_name")
    config.sts_user_id = cfg.get('sts',"user_id")
    #config.sts_email = cfg.get('sts',"email")

    config.iam_access_key = cfg.get('iam',"access_key")
    config.iam_secret_key = cfg.get('iam',"secret_key")
    config.iam_display_name = cfg.get('iam',"display_name")
    config.iam_user_id = cfg.get('iam',"user_id")
    #config.iam_email = cfg.get('iam',"email")

    config.s3_main_access_key = cfg.get('s3 main',"access_key")
    config.s3_main_secret_key = cfg.get('s3 main',"secret_key")
    config.s3_main_display_name = cfg.get('s3 main',"display_name")
    config.s3_main_user_id = cfg.get('s3 main',"user_id")
    #config.s3_main_email = cfg.get('s3 main',"email")

def teardown():
    pass

def get_sts_client(client_config=None):
    if client_config == None:
        client_config = Config(signature_version='s3v4')
    client = boto3.client(service_name='sts',
                        aws_access_key_id=config.sts_access_key,
                        aws_secret_access_key=config.sts_secret_key,
                        endpoint_url=config.default_endpoint,
                        region_name='')
    return client

def get_iam_client(client_config=None):
    if client_config == None:
        client_config = Config(signature_version='s3v4')
    client = boto3.client(service_name='iam',
                        aws_access_key_id=config.iam_access_key,
                        aws_secret_access_key=config.iam_secret_key,
                        endpoint_url=config.default_endpoint,
                        region_name='')
    return client

def get_s3_client(client_config=None):
    if client_config == None:
        client_config = Config(signature_version='s3v4')
    client = boto3.client(service_name='s3',
                        aws_access_key_id=config.s3_main_access_key,
                        aws_secret_access_key=config.s3_main_secret_key,
                        endpoint_url=config.default_endpoint,
                        region_name='')
    return client

def sts_access_key():
    return config.sts_access_key
