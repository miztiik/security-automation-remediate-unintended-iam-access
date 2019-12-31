# -*- coding: utf-8 -*-
import json
import logging
import boto3
import os

from botocore.exceptions import ClientError

__author__      = 'Mystique'
__email__       = 'miztiik@github'
__version__     = '0.0.1'
__status__      = 'production'


class global_args:
    LOG_LEVEL                   = logging.INFO
    MAX_POLICY_PER_USER         = 10


def set_logging(lv=global_args.LOG_LEVEL):
    logging.basicConfig(level=lv)
    logger = logging.getLogger()
    logger.setLevel(lv)
    return logger


LOGGER = set_logging(logging.INFO)


def revoke_iam_by_inline_policy(user_name):
    resp = {'status': False,}
    client = boto3.client('iam')
    try:
        _policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "iam:*",
                    "Resource": "*",
                    "Effect": "Deny",
                    "Sid": "DenyIAMPermissions"
                }
            ]
        }
        a_resp = client.put_user_policy(
            UserName=user_name,
            PolicyName='deny_iam_privileges',
            PolicyDocument=json.dumps(_policy)
            )
        if a_resp['ResponseMetadata']['HTTPStatusCode'] == 200:
            resp['status'] = True
    except ClientError as e:
        LOGGER.error(f"Unable to add inline Policy. ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp


def revoke_iam_access(user_name):
    resp = {'status': False,}
    client = boto3.client('iam')
    try:
        curr_managed_policies_attached = len(client.list_attached_user_policies(UserName=user_name)['AttachedPolicies'])
        if  curr_managed_policies_attached < global_args.MAX_POLICY_PER_USER:
            a_resp = client.attach_user_policy(
                UserName=user_name,
                PolicyArn=os.environ.get('DENY_IAM_POLICY_ARN')
                )
            if a_resp['ResponseMetadata']['HTTPStatusCode'] == 200:
                resp['status'] = True
                resp['iam_privileges_revoked'] = True
        else:
            a_resp = revoke_iam_by_inline_policy(user_name)
            if a_resp:
                resp['iam_privileges_revoked'] = True
                resp['status'] = True
    except ClientError as e:
        LOGGER.error(f"Unable to add policy. ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp


def is_user_admin(user_name):
    resp = {'status': False,'is_admin':False}
    client = boto3.client('iam')
    try:
        g_resp = client.list_groups_for_user( UserName = user_name )
        for g in g_resp['Groups']:
            if g['GroupName'] == os.environ.get('ADMIN_GROUP_NAME'):
                LOGGER.info(f"User is member of group:{g['GroupName']}")
                resp['is_admin'] = True
                break
        resp['status'] = True
    except ClientError as e:
        LOGGER.error(f"Unable to get {user_name} group membership. ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp


def lambda_handler(event, context):
    resp = {'status': False}
    LOGGER.info(f'Event:{event}')

    if not 'ADMIN_GROUP_NAME' in os.environ or not 'DENY_IAM_POLICY_ARN' in os.environ:
        resp['error_message'] = f'ADMIN_GROUP_NAME or DENY_IAM_POLICY_ARN is NOT provided'
        return resp

    if 'detail' not in event or 'userName' not in event['detail']['userIdentity'] or event['detail']['userIdentity']['type'] != 'IAMUser':
        resp['error_message'] = f"Action not triggered by IAMUser"
        return resp

    user_name = event['detail']['userIdentity']['userName']
    resp['user_name'] = user_name
    g_resp = is_user_admin(user_name)

    if not g_resp.get('status'):
        resp['error_message'] = g_resp.get('error_message')

    resp['is_admin']=g_resp.get('is_admin')

    # Revoke Access, if NOT Admin
    if not resp['is_admin']:
        r_resp = revoke_iam_access(user_name)
        resp['status'] = r_resp.get('status')
        resp['iam_privileges_revoked'] = r_resp.get('iam_privileges_revoked')

    LOGGER.info(resp)
    return resp
