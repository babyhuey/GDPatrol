from os import remove
from random import randrange
from shutil import make_archive

import boto3


def run():
    regions = []
    ec2 = boto3.client("ec2")
    sts = boto3.client("sts")
    response = ec2.describe_regions()
    for i in response["Regions"]:
        regions.append(i["RegionName"])

    output_filename = "GDPatrol"
    with open("role_policy.json") as rp:
        assume_role_policy = rp.read()
    zipped = make_archive(output_filename, "zip", root_dir="GDPatrol")

    with open("lambda_policy.json") as lp:
        lambda_policy = lp.read()

    iam = boto3.client("iam")
    # delete the role if it already exists, so it can be deployed with
    # the latest configuration
        
    for response in iam.get_paginator('list_roles').paginate():
        for role in response['Roles']:
            if role["RoleName"] == "GDPatrolRole":
                iam.delete_role_policy(
                    RoleName="GDPatrolRole", 
                    PolicyName="GDPatrol_lambda_policy"
                )
                iam.delete_role(RoleName="GDPatrolRole")

    created_role = iam.create_role(
        RoleName="GDPatrolRole", AssumeRolePolicyDocument=assume_role_policy
    )
    lambda_role_arn = created_role["Role"]["Arn"]

    iam.put_role_policy(
        RoleName="GDPatrolRole",
        PolicyName="GDPatrol_lambda_policy",
        PolicyDocument=lambda_policy,
    )

    for region in regions:
        lmb = boto3.client("lambda", region_name=region)
        cw_events = boto3.client("events", region_name=region)
        gd = boto3.client("guardduty", region_name=region)
        if not gd.list_detectors()["DetectorIds"]:
            created_detector = gd.create_detector(Enable=True)
            print(
                "Created GuardDuty detector: {}".format(created_detector["DetectorId"])
            )
        else:
            # gd.update_detector(
            #     DetectorId=gd.list_detectors()["DetectorIds"][0], Enable=True
            # )
            print(
                "Detector already exists: {}".format(
                    gd.list_detectors()["DetectorIds"][0]
                )
            )

        try:
            lmb.get_function(FunctionName="GDPatrol")
            lmb.delete_function(FunctionName="GDPatrol")
        except:
            pass
        lambda_response = lmb.create_function(
            FunctionName="GDPatrol",
            Runtime="python3.9",
            Role=lambda_role_arn,
            Handler="lambda_function.lambda_handler",
            Layers=[
                f"arn:aws:lambda:us-east-1:{sts.get_caller_identity()['Account']}:layer:slack:1"
            ],
            Code={"ZipFile": open(zipped, "rb").read()},
            Timeout=300,
            MemorySize=128,
        )
        target_arn = lambda_response["FunctionArn"]
        target_id = "Id" + str(randrange(10**11, 10**12))

        # Remove targets and delete the CloudWatch rule before recreating it
        rules = cw_events.list_rules(NamePrefix="GDPatrol")["Rules"]
        for rule in rules:
            if rule["Name"] == "GDPatrol":
                targets = cw_events.list_targets_by_rule(Rule=rule["Name"])["Targets"]
                for target in targets:
                    cw_events.remove_targets(Rule=rule["Name"], Ids=[target["Id"]])
                cw_events.delete_rule(Name="GDPatrol")
        created_rule = cw_events.put_rule(
            Name="GDPatrol",
            EventPattern='{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}',
        )
        cw_events.put_targets(
            Rule="GDPatrol",
            Targets=[{"Id": target_id, "Arn": target_arn, "InputPath": "$.detail"}],
        )

        # We are adding the trigger to the Lambda function so that it will be invoked every time  a finding is sent over
        statement_id = str(randrange(10**11, 10**12))
        lmb.add_permission(
            FunctionName=lambda_response["FunctionName"],
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
            SourceArn=created_rule["RuleArn"],
        )
        print(
            "Successfully deployed the GDPatrol lambda function in region {}.".format(
                str(region)
            )
        )

        # Create DynamoDB table if not existed
        dynamodb_client = boto3.client('dynamodb')
        try:
            response = dynamodb_client.create_table(
                AttributeDefinitions=[
                    {
                        'AttributeName': 'network_acl_id',
                        'AttributeType': 'S',
                    },
                    {
                        'AttributeName': 'created_at',
                        'AttributeType': 'S',
                    },
                ],
                KeySchema=[
                    {
                        'AttributeName': 'network_acl_id',
                        'KeyType': 'HASH',
                    },
                    {
                        'AttributeName': 'created_at',
                        'KeyType': 'RANGE',
                    },
                ],
                BillingMode='PAY_PER_REQUEST',
                TableName='GDPatrol',
            )
        except dynamodb_client.exceptions.ResourceInUseException:
            pass


    remove(zipped)


if __name__ == "__main__":
    run()
