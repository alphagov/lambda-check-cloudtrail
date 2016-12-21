from collections import defaultdict
from itertools import groupby

import datetime
import argparse
import logging
import boto3
import re
import os


logger = logging.getLogger()
logger.setLevel(logging.INFO)

LONG_TIME_AGO = datetime.datetime(1970,1,1)

# Matches the prefix, account_id and region the cloudtrail logs originate from
account_details_regex = re.compile(r'^(?P<prefix>[\w,-,_]+)/AWSLogs/(?P<account_id>[0-9]+)/CloudTrail/(?P<region>[0-9,a-z,-]+)/')

def get_account_details(s3_object):
    key = s3_object['Key']
    match = account_details_regex.match(key)
    assert(match != None)
    return match.groupdict()

def get_last_modified(s3_object):
    last_modified = s3_object['LastModified']
    return last_modified.replace(tzinfo=None)

def discover_cloudtrails(bucket_name):
    """Given a bucket which contains CloudTrail logs from multiple different
    AWS Accounts this will find details of the accounts which are sending logs
    into the bucket.
    """
    s3 = boto3.client('s3')

    cloudtrails_last_updated = defaultdict(lambda: LONG_TIME_AGO)
    for s3_object in s3.list_objects(Bucket=bucket_name)['Contents']:
        details = tuple(get_account_details(s3_object).items())
        last_modified = get_last_modified(s3_object)
        if cloudtrails_last_updated[details] < last_modified:
            cloudtrails_last_updated[details] = last_modified

    cloudtrails = []
    for account_details, last_updated in cloudtrails_last_updated.items():
        cloudtrail = dict(account_details)
        cloudtrail.update({'last_updated': last_updated})
        cloudtrails.append(cloudtrail)
    return cloudtrails

def find_disabled_cloudtrails(cloudtrails):
    today = datetime.datetime.today()
    yesterday = today - datetime.timedelta(days=1)
    yesterday = yesterday.replace(hour=0, minute=0)

    ct_disabled_accounts = set()
    ct_disabled_regions = filter(lambda ct: ct['last_updated'] < yesterday, cloudtrails)
    cloudtrails = sorted(cloudtrails, key=lambda ct: ct['account_id'])
    for account_id, cloudtrails in groupby(cloudtrails, key=lambda ct: ct['account_id']):
        account_latest_update = max(cloudtrails, key=lambda ct: ct['last_updated'])['last_updated']
        if account_latest_update < yesterday:
            ct_disabled_accounts.add(account_id)

    return ct_disabled_accounts, ct_disabled_regions

def notify_admins(topic_arn, disabled_cloudtrails):
    sns = boto3.client('sns')

    subject = "Accounts found with no CloudTrail activity"
    body = "The following accounts appear to have no activity for the last 24hrs. \n"
    body += str(disabled_cloudtrails)
    response = sns.publish(TopicArn=topic_arn, Message=body, Subject=subject)
    logger.info("Response: " + str(response))

def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    logger.info("Context: " + str(context))
    bucket_name = os.environ['BUCKET_NAME']
    topic_arn = os.environ['TOPIC_ARN']
    cloudtrails = discover_cloudtrails(bucket_name)
    disabled_accounts, disabled_regions = find_disabled_cloudtrails(cloudtrails)
    # TODO: choose how to notify if CloudTrail is disabled on a region
    if disabled_accounts:
        logger.warn("Found disabled CloudTrails")
        notify_admins(topic_arn, disabled_accounts)
    else:
        logger.info("All CloudTrails are up to date")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('bucket_name')
    args = parser.parse_args()

    cloudtrails = discover_cloudtrails(args.bucket_name)
    disabled_accounts, _ = find_disabled_cloudtrails(cloudtrails)
    if len(disabled_accounts) == 0:
        exit(0)
    else:
        print disabled_accounts
        exit(1)
