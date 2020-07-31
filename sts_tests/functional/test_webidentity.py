import boto3
import botocore.session
from botocore.exceptions import ClientError
from botocore.exceptions import ParamValidationError
from nose.tools import eq_ as eq
from nose.plugins.attrib import attr
from nose.plugins.skip import SkipTest
import isodate
import email.utils
import datetime
import threading
import re
import pytz
from collections import OrderedDict
import requests
import json
import base64
import hmac
import hashlib
import xml.etree.ElementTree as ET
import time
import operator
import nose
import os
import string
import random
import socket
import ssl
import logging
from collections import namedtuple

from email.header import decode_header

from . import(
    get_iam_client,
    get_sts_client,
    get_s3_client,
    get_default_endpoint,
    get_bucket_name,
    get_policy_name,
    get_role_name,
    get_role_session_name,
    get_thumbprint,
    get_aud,
    get_token
    )

def create_role(iam_client,path,rolename,policy_document,description,sessionduration,permissionboundary):
    role_response=""
    role_err=None
    if rolename is None:
        rolename=get_role_name()
    try:
    	role_response = iam_client.create_role(Path=path,RoleName=rolename,AssumeRolePolicyDocument=policy_document,)
    except ClientError as e:
    	role_err = e.response['Code']
    return (role_err,role_response,rolename)

def put_role_policy(iam_client,rolename,policyname,role_policy):
    role_response=""
    role_err=None
    if policyname is None:
        policyname=get_policy_name() 
    try:
        role_response = iam_client.put_role_policy(RoleName=rolename,PolicyName=policyname,PolicyDocument=role_policy)
    except ClientError as e:
    	role_err = e.response['Code']
    return (role_err,role_response)

@attr(resource='assume role with web identity')
@attr(method='get')
@attr(operation='check')
@attr(assertion='assuming role through web token')
def test_assume_role_with_web_identity():
    role_response=""
    role_error=None
    response=""
    role_err=None
    resp=""
    iam_client=get_iam_client()    
    sts_client=get_sts_client()
    default_endpoint=get_default_endpoint()
    role_session_name=get_role_session_name()
    thumbprint=get_thumbprint()
    aud=get_aud()
    token=get_token()
    '''
    oidc_remove=iam_client.delete_open_id_connect_provider(
    OpenIDConnectProviderArn='arn:aws:iam:::oidc-provider/localhost:8081/auth/realms/demorealm'
    )
    '''
    oidc_response = iam_client.create_open_id_connect_provider(
    Url='http://localhost:8081/auth/realms/demorealm',
    ThumbprintList=[
        thumbprint,
    ],
    )
    policy_document = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":[\""+oidc_response["OpenIDConnectProviderArn"]+"\"]},\"Action\":[\"sts:AssumeRoleWithWebIdentity\"],\"Condition\":{\"StringEquals\":{\"localhost:8081/auth/realms/demorealm:app_id\":\""+aud+"\"}}}]}"
    (role_error,role_response,general_role_name)=create_role(iam_client,'/',None,policy_document,None,None,None)
    eq(role_response['Role']['Arn'],'arn:aws:iam:::role/'+general_role_name+'')
    role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::*\"}}"
    (role_err,response)=put_role_policy(iam_client,general_role_name,None,role_policy)
    eq(response['ResponseMetadata']['HTTPStatusCode'],200)
    resp=sts_client.assume_role_with_web_identity(RoleArn=role_response['Role']['Arn'],RoleSessionName=role_session_name,WebIdentityToken=token)
    eq(resp['ResponseMetadata']['HTTPStatusCode'],200)
    s3_client = boto3.client('s3',
		aws_access_key_id = resp['Credentials']['AccessKeyId'],
		aws_secret_access_key = resp['Credentials']['SecretAccessKey'],
		aws_session_token = resp['Credentials']['SessionToken'],
		endpoint_url=default_endpoint,
		region_name='',
		)
    bucket_name = get_bucket_name()
    s3bucket = s3_client.create_bucket(Bucket=bucket_name)
    eq(s3bucket['ResponseMetadata']['HTTPStatusCode'],200)
    bkt = s3_client.delete_bucket(Bucket=bucket_name)
    eq(bkt['ResponseMetadata']['HTTPStatusCode'],204)
    oidc_remove=iam_client.delete_open_id_connect_provider(
    OpenIDConnectProviderArn=oidc_response["OpenIDConnectProviderArn"]
    )
    
