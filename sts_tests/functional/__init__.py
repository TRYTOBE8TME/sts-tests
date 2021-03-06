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
    if not cfg.has_section("webidentity"):
        raise RuntimeError('Your config file is missing the "webidentity" section!')

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

    config.webidentity_thumbprint = cfg.get('webidentity', "thumbprint")
    config.webidentity_aud = cfg.get('webidentity', "aud")
    config.webidentity_token = cfg.get('webidentity', "token")
    config.webidentity_realm = cfg.get('webidentity', "KC_REALM")
    config.webidentity_client = cfg.get('webidentity', "KC_CLIENT")

def teardown():
    pass

def get_sts_client(client_config=None):
    if client_config == None:
        client_config = Config(signature_version='s3v4')
    client = boto3.client(service_name='sts',
                        aws_access_key_id=config.sts_access_key,
                        aws_secret_access_key=config.sts_secret_key,
                        endpoint_url=config.default_endpoint,
                        use_ssl=config.default_is_secure,
                        region_name='',
                        config=client_config)
    return client

def get_iam_client(client_config=None):
    if client_config == None:
        client_config = Config(signature_version='s3v4')
    client = boto3.client(service_name='iam',
                        aws_access_key_id=config.iam_access_key,
                        aws_secret_access_key=config.iam_secret_key,
                        endpoint_url=config.default_endpoint,
                        use_ssl=config.default_is_secure,
                        region_name='',
                        config=client_config)
    return client

def get_s3_client(client_config=None):
    if client_config == None:
        client_config = Config(signature_version='s3v4')
    client = boto3.client(service_name='s3',
                        aws_access_key_id=config.s3_main_access_key,
                        aws_secret_access_key=config.s3_main_secret_key,
                        endpoint_url=config.default_endpoint,
                        use_ssl=config.default_is_secure,
                        region_name='',
                        config=client_config)
    return client

def get_bucket_name(bucket_name=None):
    if bucket_name is None:
        rand = ''.join(
        random.choice(string.ascii_lowercase + string.digits)
        for c in range(255)
        )
        while rand:
                bucket_name = '{random}'.format(random=rand)
                if len(bucket_name) <= 10:
            	        return bucket_name
                rand = rand[:-1]
    return bucket_name

def get_policy_name(policy_name=None):
    if policy_name is None:
        rand = ''.join(
        random.choice(string.ascii_lowercase + string.digits)
        for c in range(255)
        )
        while rand:
                policy_name = '{random}'.format(random=rand)
                if len(policy_name) <= 10:
            	        return policy_name
                rand = rand[:-1]
    return policy_name

def get_role_name(role_name=None):
    if role_name is None:
        rand = ''.join(
        random.choice(string.ascii_lowercase + string.digits)
        for c in range(255)
        )
        while rand:
                role_name = '{random}'.format(random=rand)
                if len(role_name) <= 10:
            	        return role_name
                rand = rand[:-1]
    return role_name

def get_role_session_name(role_session_name=None):
    if role_session_name is None:
        rand = ''.join(
        random.choice(string.ascii_lowercase + string.digits)
        for c in range(255)
        )
        while rand:
                role_session_name = '{random}'.format(random=rand)
                if len(role_session_name) <= 10:
            	        return role_session_name
                rand = rand[:-1]
    return role_session_name

def get_sts_user_id():
    return config.sts_user_id

def get_default_endpoint():
    return config.default_endpoint

def get_s3_main_access_key():
    return config.s3_main_access_key

def get_s3_main_secret_key():
    return config.s3_main_secret_key

def get_thumbprint():
    return config.webidentity_thumbprint

def get_aud():
    return config.webidentity_aud

def get_token():
    return config.webidentity_token

def get_realm_name():
    return config.webidentity_realm

def get_client_name():
    return config.webidentity_client
