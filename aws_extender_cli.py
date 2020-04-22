#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function
import argparse
import re
try:
    import urllib2 as urllib_req
    from urllib2 import HTTPError, URLError
except ImportError:
    import urllib.request as urllib_req
    from urllib.error import HTTPError, URLError
from xml.dom.minidom import parse
from xml.parsers.expat import ExpatError
import boto3
from botocore.exceptions import ClientError
from botocore.handlers import disable_signing
from botocore.parsers import ResponseParserError
from boto.https_connection import InvalidCertificateException
from boto.s3.connection import S3Connection
from boto.exception import S3ResponseError

def load_buckets(bucket_type, filepath):
    """Extract bucket names from a file."""
    with open(filepath, 'r') as buckets:
        bucket_list = buckets.read()
        if bucket_type != 'azure':
            bucket_list = re.findall(r'(?:(?:gs|s3)://)?([\w.-]+)/?', bucket_list, re.I)
        else:
            bucket_list = re.findall(r'((?:\w+://)?[\w.-]+/?)', bucket_list, re.I)
    return bucket_list

def save_output(issues, filename):
    """Save output to file."""
    with open(filename, 'a') as output:
        for issue in issues:
            output.write(issue)

def init_clients(keys_path, service):
    """Initialize clients."""
    client = None
    access_key = ''
    secret_key = ''

    if keys_path:
        with open(keys_path, 'r') as fkeys:
            keys = fkeys.read()
            try:
                access_key = re.search(r'access_?key_?id ?[=:] ?([^\s]+)', keys, re.I).group(1)
                secret_key = re.search(r'secret(?:_access_)?key ?[=:] ?([^\s]+)', keys, re.I).group(1)
            except AttributeError:
                raise ValueError('Credentials are not in the expected format. '
                                 'The expected format is:\naws_access_key_id=XXXX\naws_secret_access_key=XXXX')

    if service == 's3':
        client = boto3.client('s3', aws_access_key_id=access_key,
                              aws_secret_access_key=secret_key)
        if not keys_path:
            client.meta.events.register('choose-signer.s3.*', disable_signing)
        host = 's3.amazonaws.com'
    else:
        host = 'storage.googleapis.com'

    if keys_path:
        boto_client = S3Connection(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            host=host
        )
    else:
        boto_client = S3Connection(host=host, anon=True)
    return [client, boto_client]

def enumerate_keys(bucket, bucket_type, wordlist_path):
    """Enumerate bucket keys."""
    keys = []

    with open(wordlist_path) as wordlist:
        wordlist_keys = wordlist.read()
        key_list = wordlist_keys.split('\n')

    if bucket_type != 'azure':
        for key in key_list:
            try:
                key = bucket.get_key(key).key
                keys.append(key)
            except (S3ResponseError, AttributeError):
                continue
    else:
        bucket = bucket if bucket.endswith('/') else bucket + '/'
        for key in key_list:
            try:
                request = urllib_req.Request(bucket + key)
                urllib_req.urlopen(request, timeout=20)
                keys.append(key)
            except (HTTPError, URLError):
                continue
    return keys

def test_s3_bucket(bucket_name, clients, wordlist_path=''):
    """Test Amazon S3 buckets."""
    keys = []
    grants = []
    issues = []
    client = clients[0]
    boto_client = clients[1]

    try:
        client.head_bucket(Bucket=bucket_name)
    except ClientError as error:
        error_code = int(error.response['Error']['Code'])
        if error_code == 404:
            return

    boto_bucket = boto_client.get_bucket(bucket_name, validate=False)

    try:
        acl = client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            grantee = grant['Grantee']
            try:
                identifier = grantee['DisplayName']
            except KeyError:
                try:
                    identifier = grantee['URI']
                except KeyError:
                    identifier = grantee['ID']
            grants.append(identifier + '->' + grant['Permission'])
        issues.append('s3:GetBucketAcl\n\t* %s' % '\n\t* '.join(grants))
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:GetBucketAcl')

    try:
        client.get_bucket_cors(Bucket=bucket_name)
        issues.append('s3:GetBucketCORS')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:GetBucketCORS')

    try:
        client.get_bucket_lifecycle(Bucket=bucket_name)
        issues.append('s3:GetLifecycleConfiguration')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:GetLifecycleConfiguration')

    try:
        client.get_bucket_notification(Bucket=bucket_name)
        issues.append('s3:GetBucketNotification')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:GetBucketNotification')

    try:
        client.get_bucket_policy(Bucket=bucket_name)
        issues.append('s3:GetBucketPolicy')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:GetBucketPolicy')

    try:
        client.get_bucket_tagging(Bucket=bucket_name)
        issues.append('s3:GetBucketTagging')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:GetBucketTagging')

    try:
        client.get_bucket_website(Bucket=bucket_name)
        issues.append('s3:GetBucketWebsite')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:GetBucketWebsite')

    try:
        client.list_multipart_uploads(Bucket=bucket_name)
        issues.append('s3:ListMultipartUploadParts')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:ListMultipartUploadParts')

    try:
        blobs = client.list_objects(Bucket=bucket_name)
        i = 0
        for key in blobs['Contents']:
            i = i + 1
            keys.append(key['Key'])
            if i == 10:
                break
        issues.append('s3:ListBucket\n\t* %s' % '\n\t* '.join(keys))
    except ClientError:
        if wordlist_path:
            keys += enumerate_keys(boto_bucket, 's3', wordlist_path)
            if keys:
                issues.append('s3:ListBucket\n\t* %s' % '\n\t* '.join(keys))
    except ResponseParserError:
        issues.append('s3:ListBucket')

    try:
        client.put_bucket_cors(
            Bucket=bucket_name,
            CORSConfiguration={
                'CORSRules': [
                    {
                        'AllowedMethods': [
                            'GET'
                        ],
                        'AllowedOrigins': [
                            '*'
                        ]
                    }
                ]
            }
        )
        issues.append('s3:PutBucketCORS')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:PutBucketCORS')

    try:
        client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration={
                'Rules': [
                    {
                        'Status': 'Disabled',
                        'Prefix': 'test'
                    }
                ]
            }
        )
        issues.append('s3:PutLifecycleConfiguration')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:PutLifecycleConfiguration')

    try:
        client.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus={}
        )
        issues.append('s3:PutBucketLogging')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:PutBucketLogging')

    try:
        client.put_bucket_notification(
            Bucket=bucket_name,
            NotificationConfiguration={
                'TopicConfiguration': {
                    'Events': ['s3:ReducedRedundancyLostObject'],
                    'Topic': 'arn:aws:sns:us-west-2:444455556666:sns-topic-one'
                }
            }
        )
        issues.append('s3:PutBucketNotification')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:PutBucketNotification')

    try:
        client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={
                'TagSet': [
                    {
                        'Key': 'test',
                        'Value': 'test'
                    },
                ]
            }
        )
        issues.append('s3:PutBucketTagging')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:PutBucketTagging')

    try:
        client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                'ErrorDocument': {
                    'Key': 'test'
                },
                'IndexDocument': {
                    'Suffix': 'test'
                }
            }
        )
        issues.append('s3:PutBucketWebsite')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:PutBucketWebsite')

    try:
        client.put_object(
            ACL='public-read-write',
            Body=b'test',
            Bucket=bucket_name,
            Key='test.txt'
        )
        issues.append('s3:PutObject\n\t* test.txt')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:PutObject\n\t* test.txt')

    if '.' in bucket_name:
        try:
            client.put_bucket_acl(
                GrantFullControl='uri="http://acs.amazonaws.com/groups/global/AllUsers"',
                Bucket=bucket_name
            )
            issues.append('s3:PutBucketAcl')
        except ClientError:
            pass
        except ResponseParserError:
            issues.append('s3:PutBucketAcl')
    else:
        try:
            boto_bucket.add_email_grant('FULL_CONTROL', 0)
            issues.append('s3:PutBucketAcl')
        except S3ResponseError as error:
            if error.error_code == 'UnresolvableGrantByEmailAddress':
                issues.append('s3:PutBucketAcl')

    try:
        client.put_bucket_policy(
            Bucket=bucket_name,
            Policy='''
                {
                    "Version":"2012-10-17",
                    "Statement": [
                        {
                            "Effect":"Allow",
                            "Principal": "*",
                            "Action":["s3:GetBucketPolicy"],
                            "Resource":["arn:aws:s3:::%s/*"]
                        }
                    ]
                } ''' % bucket_name
        )
        issues.append('s3:PutBucketPolicy')
    except ClientError:
        pass
    except ResponseParserError:
        issues.append('s3:PutBucketPolicy')

    if not issues:
        issues = ['None']

    issuedetail = '===== (%s) =====\n[*] %s\n\n' % (bucket_name,
                                                    '\n[*] '.join(issues))
    return issuedetail

def test_gs_bucket(bucket_name, clients, wordlist_path=''):
    """Test Google Storage buckets."""
    keys = []
    issues = []
    boto_client = clients[1]
    bucket = boto_client.get_bucket(bucket_name, validate=False)

    try:
        boto_client.head_bucket(bucket_name)
    except S3ResponseError as error:
        if error.error_code == 'NoSuchBucket':
            return
    except InvalidCertificateException:
        return

    try:
        i = 0
        for k in bucket.list():
            i = i + 1
            keys.append(k.key)
            if i == 10:
                break
        issues.append('READ\n\t* %s' % '\n\t* '.join(keys))
    except S3ResponseError:
        if wordlist_path:
            keys += enumerate_keys(bucket, 'gs', wordlist_path)
            if keys:
                issues.append('READ\n\t* %s' % '\n\t* '.join(keys))

    try:
        key = bucket.new_key('test.txt')
        key.set_contents_from_string('test')
        issues.append('WRITE\n\t* test.txt')
    except S3ResponseError:
        pass

    try:
        bucket.add_email_grant('FULL_CONTROL', 0)
        issues.append('FULL_CONTROL')
    except S3ResponseError as error:
        if error.error_code == 'UnresolvableGrantByEmailAddress':
            issues.append('FULL_CONTROL')
    except AttributeError as error:
        if error.message.startswith("'Policy'"):
            issues.append('FULL_CONTROL')
        else:
            raise

    if not issues:
        issues = ['None']

    issuedetail = '===== (%s) =====\n[*] %s\n\n' % (bucket_name,
                                                    '\n[*] '.join(issues))
    return issuedetail

def test_az_bucket(bucket_uri, _, wordlist_path=''):
    """Test Azure buckets."""
    issues = []
    keys = []

    if not re.search(r'^\w+://', bucket_uri):
        bucket_uri = 'https://' + bucket_uri

    try:
        request = urllib_req.Request(bucket_uri + '?comp=list&maxresults=10')
        response = urllib_req.urlopen(request, timeout=20)
        blobs = parse(response).documentElement.getElementsByTagName('Name')
        for blob in blobs:
            keys.append(blob.firstChild.nodeValue.encode('utf-8'))
        issues.append('Full public read access\n\t* %s' % '\n\t* '.join(keys))
    except (HTTPError, AttributeError):
        if wordlist_path:
            keys += enumerate_keys(bucket_uri, 'azure', wordlist_path)
            if keys:
                issues.append('Public read access for blobs only\n\t* %s' %
                              '\n\t* '.join(keys))
    except (URLError, ExpatError):
        return

    if not issues:
        issues = ['None']

    issuedetail = '===== (%s) =====\n[*] %s\n\n' % (bucket_uri,
                                                    '\n[*] '.join(issues))
    return issuedetail

def main():
    """Execute main code."""
    issue = None
    issues = []
    parser = argparse.ArgumentParser()
    exclusive_args = parser.add_mutually_exclusive_group(required=True)
    exclusive_args.add_argument('-f', '--filepath',
                                help='the path of a bucket names list')
    exclusive_args.add_argument('-b', '--bucket',
                                help='the name of the bucket to test')
    parser.add_argument('-w', '--wordlist', help='a wordlist filepath')
    parser.add_argument('-o', '--output', help='an output filename')
    parser.add_argument('-k', '--keys',
                        help='the path of your credentials file')
    required_args = parser.add_argument_group('required arguments')
    required_args.add_argument('-s', '--service', required=True, type=str.lower,
                               help='The name of the storage service ("S3", "GS", or "Azure").')
    args = parser.parse_args()
    service = args.service
    wordlist_path = args.wordlist

    if args.filepath:
        buckets = load_buckets(service, args.filepath)
    elif args.bucket:
        buckets = [args.bucket]

    if service == 's3':
        test_fn = test_s3_bucket
    elif service == 'gs':
        test_fn = test_gs_bucket
    elif service == 'azure':
        test_fn = test_az_bucket
    else:
        parser.parse_args(['-h'])

    clients = init_clients(args.keys, service)

    for bucket in buckets:
        issue = test_fn(bucket, clients, wordlist_path)
        if issue:
            issues.append(issue)

    if issues:
        if args.output:
            save_output(issues, args.output)
        else:
            print(''.join(issues).strip())

if __name__ == '__main__':
    main()
