# aws_user_enum V1.0

This script is intended to enumerate aws IAM users against a target AWS account. It shuffles between the below supported services in order to test adding a policy for each remote IAM user. 

Supported AWS Services
- IAM Assume Role
- S3 Bucket Policy
- KMS Policy
- SQS Access Policy
- SNS Topic Policy

The script accepts arguments for a target AWS account to test as well as a wordlist of potential usernames to test with. Optional arguments can be provided to tune running of the script as desired. The following steps are completed each run of the script. Out is by default saved to "./aws_user_enum.log"

1. Check if specifed or default resource exists for each of the declared AWS services
2. If the specified or default resources do not exist, prompts if those resources should be created. Note that KMS keys take 7 days at minimum to be removed.
3. Work through each username in provided wordlist. During this process the script will shuffle through a list of verified services to test against. Additionally, the script will any existing policy, attempt to add the user to the policy, and restore the original policy afterward. With verbose mode the "[!] Invalid Principal" results signify IAM users that do not exist in the target AWS account. Successfully identified IAM User accounts in the target account output in the format "[+] \<acct-id\>/\<iam-user\>".
4. After finishing the wordlist, the script will attempt to delete the AWS resources it used unless the `--save_services` argument is provided on run.

## Setup
1. `python3 -m venv .venv`
2. `source .venv/bin/activate`
3. `python3 -m pip install -r requirements.txt --upgrade`

## Run
Help Ouptut
```
> $ python3 aws_user_enum.py -h
usage: aws_user_enum.py [-h] [--credentials_file CREDENTIALS_FILE] [--profile PROFILE] [--access_key_id ACCESS_KEY_ID]
                        [--secret_access_key SECRET_ACCESS_KEY] [--session_token SESSION_TOKEN] [--region REGION] [--debug] [--verbose]
                        [--delay DELAY] [-a [ACCOUNTS [ACCOUNTS ...]]] -w WORDLIST [--shuffle] [--services [SERVICES [SERVICES ...]]]
                        [--save_services] [--iam_role IAM_ROLE] [--s3_bucket S3_BUCKET] [--kms_key KMS_KEY] [--kms_alias KMS_ALIAS]
                        [--sqs SQS] [--sns SNS]

AWS IAM User ENumeration using various AWS Services.

optional arguments:
  -h, --help            show this help message and exit
  --credentials_file CREDENTIALS_FILE
                        Location of AWS Credentials file. Defaults to /home/pdmayo/.aws/credentials
  --profile PROFILE     Specify profile in credentials file to use. Defaults to 'default'.
  --access_key_id ACCESS_KEY_ID
                        Specify an AWS Access Key ID
  --secret_access_key SECRET_ACCESS_KEY
                        Specify an AWS Secret Access Key
  --session_token SESSION_TOKEN
                        Specify a temporary AWS Session Token
  --region REGION       Specify the region for test AWS resources.
  --debug               Enable debug logging.
  --verbose             Report output every step of the way.
  --delay DELAY         Set script delay in seconds between policy application attemptes.
  -a [ACCOUNTS [ACCOUNTS ...]], --accounts [ACCOUNTS [ACCOUNTS ...]]
                        Target AWS Accounts to brute force.
  -w WORDLIST, --wordlist WORDLIST
                        Username wordlist with one user per line.
  --shuffle             Shuffle the provided wordlist.
  --services [SERVICES [SERVICES ...]]
                        Specify which service to test with. 'all' will use all supported services. [IAM, S3, KMS, SQS, SNS]
  --save_services       Do not remove AWS services when finished.
  --iam_role IAM_ROLE   IAM Role to use during testing.
  --s3_bucket S3_BUCKET
                        S3 Bucket to use during testing.
  --kms_key KMS_KEY     KMS Key ID to use during testing.
  --kms_alias KMS_ALIAS
                        KMS Key alias to use during testing.
  --sqs SQS             SQS to use during testing.
  --sns SNS             SNS Trail to use during testing.
```

`python3 aws_user_enum.py -a 123456789012 -p target_profile`