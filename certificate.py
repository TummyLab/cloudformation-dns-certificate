"""
Lambda function backing cloudformation certificate resource

Post-minification, this module must be less than 4KiB.

"""

import time
import boto3
import hashlib
import json
import copy
import logging
from botocore.vendored import requests

l = logging.getLogger()
l.setLevel(logging.INFO)


def send(event):
    l.info(event)
    resp = requests.put(event['ResponseURL'], data=json.dumps(event))
    l.info(resp)



def create_cert(acm, props, i_token):
    a = copy.copy(props)

    del a['ServiceToken']

    if 'Tags' in props:
        del a['Tags']

    if 'ValidationMethod' in props:
        if props['ValidationMethod'] == 'DNS':

            try:
                for name in set([props['DomainName']] + props.get('SubjectAlternativeNames', [])):
                    get_zone_for(name, props)
            except KeyError:
                raise RuntimeError('Validation opts missing')

            del a['DomainValidationOptions']

        elif props['ValidationMethod'] == 'EMAIL':
            del a['ValidationMethod']

    return acm.request_certificate(
        IdempotencyToken=i_token,
        **a
    )['CertificateArn']


def add_tags(acm, arn, props):
    if 'Tags' in props:
        acm.add_tags_to_certificate(CertificateArn=arn, Tags=props['Tags'])


def get_zone_for(name, props):
    name = name.rstrip('.')
    hosted_zones = {v['DomainName'].rstrip('.'): v['HostedZoneId'] for v in props['DomainValidationOptions']}

    components = name.split('.')

    while len(components):
        if '.'.join(components) in hosted_zones:
            return hosted_zones['.'.join(components)]

        components = components[1:]

    raise RuntimeError('Validation opts missing (%s)' % str(name))

def validate(acm, arn, props):
    if 'ValidationMethod' in props and props['ValidationMethod'] == 'DNS':

        all_records_created = False
        while not all_records_created:
            all_records_created = True

            certificate = acm.describe_certificate(CertificateArn=arn)['Certificate']
            l.info(certificate)

            if certificate['Status'] != 'PENDING_VALIDATION':
                return

            for v in certificate['DomainValidationOptions']:

                if 'ValidationStatus' not in v or 'ResourceRecord' not in v:
                    all_records_created = False
                    continue

                if v['ValidationStatus'] == 'PENDING_VALIDATION':
                    response = boto3.client('route53').change_resource_record_sets(
                        HostedZoneId=get_zone_for(v['DomainName'], props),
                        ChangeBatch={
                            'Comment': 'Domain validation for %s' % arn,
                            'Changes': [{
                                'Action': 'UPSERT',
                                'ResourceRecordSet': {
                                    'Name': v['ResourceRecord']['Name'],
                                    'Type': v['ResourceRecord']['Type'],
                                    'TTL': 60,
                                    'ResourceRecords': [{
                                        'Value': v['ResourceRecord']['Value']
                                    }]
                                }
                            }]
                        }
                    )

                    l.info(response)

            time.sleep(1)


def replace_cert(event):
    old = copy.copy(event['OldResourceProperties'])
    if 'Tags' in old:
        del old['Tags']

    new = copy.copy(event['ResourceProperties'])
    if 'Tags' in new:
        del new['Tags']

    return old != new


def wait_for_issuance(acm, arn, context):
    while (context.get_remaining_time_in_millis() / 1000) > 30:

        certificate = acm.describe_certificate(CertificateArn=arn)['Certificate']
        l.info(certificate)
        if certificate['Status'] == 'ISSUED':
            return True
        elif certificate['Status'] == 'FAILED':
            raise RuntimeError(certificate.get('FailureReason', 'Failed to issue certificate'))

        time.sleep(5)

    return False


def reinvoke(event, context):
    # Only continue to reinvoke for 8 iterations
    event['I'] = event.get('I', 0) + 1
    if event['I'] > 8:
        raise RuntimeError('Timer expired')

    l.info('Reinvoking for the %i time' % event['I'])
    l.info(event)
    boto3.client('lambda').invoke(
        FunctionName=context.invoked_function_arn,
        InvocationType='Event',
        Payload=json.dumps(event).encode()
    )


def handler(event, context):
    l.info(event)
    try:
        i_token = hashlib.new('md5', (event['RequestId'] + event['StackId']).encode()).hexdigest()
        props = event['ResourceProperties']

        acm = boto3.client('acm', region_name=props.pop('Region', None))

        if event['RequestType'] == 'Create':
            event['PhysicalResourceId'] = 'None'
            event['PhysicalResourceId'] = create_cert(acm, props, i_token)
            add_tags(acm, event['PhysicalResourceId'], props)
            validate(acm, event['PhysicalResourceId'], props)

            if wait_for_issuance(acm, event['PhysicalResourceId'], context):
                event['Status'] = 'SUCCESS'
                return send(event)
            else:
                return reinvoke(event, context)

        elif event['RequestType'] == 'Delete':
            if event['PhysicalResourceId'] != 'None':
                acm.delete_certificate(CertificateArn=event['PhysicalResourceId'])
            event['Status'] = 'SUCCESS'
            return send(event)

        elif event['RequestType'] == 'Update':
            if replace_cert(event):
                event['PhysicalResourceId'] = create_cert(acm, props, i_token)
                add_tags(acm, event['PhysicalResourceId'], props)
                validate(acm, event['PhysicalResourceId'], props)

                if not wait_for_issuance(acm, event['PhysicalResourceId'], context):
                    return reinvoke(event, context)
            else:
                if 'Tags' in event['OldResourceProperties']:
                    acm.remove_tags_from_certificate(CertificateArn=event['PhysicalResourceId'],
                                                     Tags=event['OldResourceProperties']['Tags'])

                add_tags(acm, event['PhysicalResourceId'], props)

            event['Status'] = 'SUCCESS'
            return send(event)
        else:
            raise RuntimeError('Unknown RequestType')

    except Exception as ex:
        l.exception('')
        event['Status'] = 'FAILED'
        event['Reason'] = str(ex)
        return send(event)
