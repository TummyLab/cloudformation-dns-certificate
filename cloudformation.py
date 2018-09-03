from troposphere import Template, Sub, Ref, GetAtt, Output
import troposphere.iam as iam
import troposphere.awslambda as awslambda
from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal
from troposphere.cloudformation import CustomResource


def create_template():
    template = Template(
        Description='DNS Validated ACM Certificate Example'
    )
    template.add_version()

    lambda_role = template.add_resource(iam.Role('CustomAcmCertificateLambdaExecutionRole',
        AssumeRolePolicyDocument=PolicyDocument(
            Version='2012-10-17',
            Statement=[
                Statement(
                    Effect=Allow,
                    Action=[Action('sts', 'AssumeRole')],
                    Principal=Principal('Service', 'lambda.amazonaws.com')
                )
            ],
        ),
        Path="/",
        ManagedPolicyArns=[
            'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
            'arn:aws:iam::aws:policy/service-role/AWSLambdaRole'
        ],
        Policies=[iam.Policy('CustomAcmCertificateLambdaPolicy',
            PolicyName=Sub('${AWS::StackName}-CustomAcmCertificateLambdaExecutionPolicy'),
            PolicyDocument=PolicyDocument(
                Version='2012-10-17',
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[
                            Action('acm', 'AddTagsToCertificate'),
                            Action('acm', 'DeleteCertificate'),
                            Action('acm', 'DescribeCertificate'),
                            Action('acm', 'RemoveTagsFromCertificate'),
                            Action('acm', 'RequestCertificate')
                        ],
                        Resource=[Sub('arn:aws:acm:*:${AWS::AccountId}:certificate/*')]
                    ),
                    Statement(
                        Effect=Allow,
                        Action=[
                            Action('acm', 'RequestCertificate')
                        ],
                        Resource=['*']
                    ),
                    Statement(
                        Effect=Allow,
                        Action=[
                            Action('route53', 'ChangeResourceRecordSets')
                        ],
                        Resource=['arn:aws:route53:::hostedzone/*']
                    )
                ]
            ),
        )],
    ))

    with open('certificate_min.py', 'r') as f:
        code = f.read()

    certificate_lambda = template.add_resource(awslambda.Function('CustomAcmCertificateLambda',
        Code=awslambda.Code(ZipFile=code),
        Runtime='python3.6',
        Handler='index.handler',
        Timeout=300,
        Role=GetAtt(lambda_role, 'Arn'),
        Description='Cloudformation custom resource for DNS validated certificates',
        Metadata={
            'Source': 'https://github.com/dflook/cloudformation-dns-certificate',
            'Version': '1.2.0'
        }
    ))

    certificate = template.add_resource(CustomResource('ExampleCertificate',
        ServiceToken=GetAtt(certificate_lambda, 'Arn'),
        ValidationMethod='DNS',
        DomainName='test.example.com',
        DomainValidationOptions=[
            {
                'DomainName': 'test.example.com',
                'HostedZoneId': 'Z2KZ5YTUFZNC7H'
            }
        ],
        Tags=[{
            'Key': 'Name',
            'Value': 'Example Certificate'
        }],
        Region='us-east-1'
    ))

    template.add_output(Output(
        "CertificateARN",
        Value=Ref(certificate),
        Description="The ARN of the example certificate"
    ))

    return template

if __name__ == '__main__':
    template = create_template()

    with open('cloudformation.yaml', 'w') as f:
        f.write(template.to_yaml())

    with open('cloudformation.json', 'w') as f:
        f.write(template.to_json())
