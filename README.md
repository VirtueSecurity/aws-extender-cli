# AWS Extender CLI

AWS Extender CLI is a command-line script to test S3 buckets as well as Google Storage buckets and Azure Storage containers for common misconfiguration issues using the boto/boto3 SDK library.

## Installing Dependencies
Both of [boto](https://github.com/boto/boto) and [boto3](https://github.com/boto/boto3) are required. You can install them using [pip](https://en.wikipedia.org/wiki/Pip_\(package_manager\)):

    $ pip install -r requirements.txt

## CLI Arguments
Below is a description of supported arguments:

| Argument   |      Description      |      Required      |
|----------|:-------------:|:-------------:|
| -h, --help | Show a help message and exit |  False |
| -f, --filepath |  The path of a bucket names list   |    False*   |
| -b, --bucket | The name of the bucket to test | False* |
| -w, --wordlist | A wordlist filepath | False |
| -o, --output | An output filename | False |
| -k, --keys | The path of your credentials file | False |
| -s, --service | the name of the storage service ("S3", "GS", or "Azure") | True |

#### Notes:
* Mutually exclusive arguments are denoted by an asterisk.
* The `-k/--keys` argument expects the filepath of your [AWS](https://console.aws.amazon.com/iam/home?#/security_credential)/[GS](https://cloud.google.com/storage/docs/migrating#keys) keys. The keys are expected to be in the following format:
```
aws_access_key_id=XXXXXXXXXXXXXXXXXXXX
aws_secret_access_key=XXXXXXXXXXXXXXXXXXXXXX
```

## Example Usage:

```bash
$ python aws_extender_cli.py -s S3 -b flaws.cloud -k keys.csv
===== (flaws.cloud) =====
[*] s3:ListMultipartUploadParts
[*] s3:ListBucket
	* hint1.html
	* hint2.html
	* hint3.html
	* index.html
	* robots.txt
	* secret-dd02c7c.html
```

