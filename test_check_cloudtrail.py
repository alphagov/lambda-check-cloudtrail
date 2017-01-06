import check_cloudtrail
import mock
import datetime

from dateutil.tz import tzutc

today = datetime.datetime.now()
two_days_ago = today - datetime.timedelta(days=2)

BUCKET_CONTENTS = {
    u'Contents': [
        {u'ETag': '"b3630875ce8a1c35d32f2f488df5c7f7"',
         u'Key': u'someprefix/AWSLogs/11111111111/CloudTrail/ap-northeast-1/2016/12/12/123123_CloudTrail_ap-northeast-1_20161212T1630Z_z9wBpTAjoz3GfFol.json.gz',
         u'LastModified': two_days_ago,
         u'Size': 0,
         u'StorageClass': 'STANDARD'},
        {u'ETag': '"4d5062130cd349e964f46dfbfc3efe5a"',
         u'Key': u'someprefix/AWSLogs/11111111111/CloudTrail/ap-northeast-1/2016/12/13/123123_CloudTrail_ap-northeast-1_20161213T1120Z_uqvFwTOgY7k0HJ7G.json.gz',
         u'LastModified': two_days_ago,
         u'Size': 100,
         u'StorageClass': 'STANDARD'},
        {u'ETag': '"001c2bd22d056cfd55488917c9a581de"',
         u'Key': u'someprefix/AWSLogs/11111111111/CloudTrail/eu-west-1/2016/12/12/123123_CloudTrail_eu-west-1_20161212T1625Z_gd8pgknS82gmbng9.json.gz',
         u'LastModified': two_days_ago,
         u'Size': 100,
         u'StorageClass': 'STANDARD'},
        {u'ETag': '"20891dd2605ba55da1e0495cef650b00"',
         u'Key': u'someprefix/AWSLogs/22222222222/CloudTrail/eu-west-1/2016/12/12/123123_CloudTrail_eu-west-1_20161212T1640Z_MiWtmqdhtb9tMvVL.json.gz',
         u'LastModified': two_days_ago,
         u'Size': 100,
         u'StorageClass': 'STANDARD'},
        {u'ETag': '"ed33daec8faa0fdca7c038ec8d473114"',
         u'Key': u'someprefix/AWSLogs/22222222222/CloudTrail/us-west-2/2016/12/13/123123_CloudTrail_us-west-2_20161213T1120Z_oWwWCNoFKyilEqjz.json.gz',
         u'LastModified': today,
         u'Size': 100,
         u'StorageClass': 'STANDARD'},
        {u'ETag': '"ed33daec8faa0fdca7c038ec8d473114"',
         u'Key': u'some-other-object-not-from-cloudtrail',
         u'LastModified': two_days_ago,
         u'Size': 0,
         u'StorageClass': 'STANDARD'}
    ]
}

EXPECTED_CLOUDTRAILS = [
    {'account_id': u'22222222222', 'last_updated': two_days_ago, 'prefix': u'someprefix', 'region': u'eu-west-1'},
    {'account_id': u'11111111111', 'last_updated': two_days_ago, 'prefix': u'someprefix', 'region': u'ap-northeast-1'},
    {'account_id': u'11111111111', 'last_updated': two_days_ago, 'prefix': u'someprefix', 'region': u'eu-west-1'},
    {'account_id': u'22222222222', 'last_updated': today, 'prefix': u'someprefix', 'region': u'us-west-2'}
]

class TestS3Client(object):
    def list_objects(*args, **kwargs):
        return BUCKET_CONTENTS

def mock_client(client_type):
    return TestS3Client()

@mock.patch('boto3.client', new=mock_client)
def test_discover_cloudtrails():
    assert sorted(check_cloudtrail.discover_cloudtrails('bucket_name'), key=lambda i: i['last_updated']) == EXPECTED_CLOUDTRAILS


def test_find_disabled_cloudtrails():
    accounts, regions = check_cloudtrail.find_disabled_cloudtrails(EXPECTED_CLOUDTRAILS)

    assert accounts == set(['11111111111'])
    assert len(regions) == 3


def test_get_account_details():
    valid_cloudtrail_key = {'Key': 'someprefix/AWSLogs/11111111111/CloudTrail/ap-northeast-1/2016/12/12/something.json.gz'}
    random_key = {'Key': 'random'}

    assert check_cloudtrail.get_account_details(valid_cloudtrail_key) == {'account_id': '11111111111', 'prefix': 'someprefix', 'region': 'ap-northeast-1'}
    assert check_cloudtrail.get_account_details(random_key) is None
