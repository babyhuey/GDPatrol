from os import remove
from random import randrange
from shutil import make_archive, copytree, rmtree
from time import sleep
import boto3
import subprocess
import sys
import argparse


def run(slack_webhook_url=None):
    regions = []
    ec2 = boto3.client("ec2")
    response = ec2.describe_regions()
    regions = [region["RegionName"] for region in response["Regions"]]

    output_filename = "GDPatrol"
    with open("role_policy.json") as rp:
        assume_role_policy = rp.read()

    copytree("GDPatrol/", "GDPatrol-build/", dirs_exist_ok=True)

    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "-r",
            "requirements.txt",
            "--target",
            "GDPatrol-build",
        ]
    )
    zipped = make_archive(output_filename, "zip", root_dir="GDPatrol-build")
    rmtree("GDPatrol-build")
    with open("lambda_policy.json") as lp:
        lambda_policy = lp.read()

    iam = boto3.client("iam")
    # delete the role if it already exists, so it can be deployed with
    # the latest configuration

    for response in iam.get_paginator("list_roles").paginate():
        for role in response["Roles"]:
            if role["RoleName"] == "GDPatrolRole":
                iam.delete_role_policy(
                    RoleName="GDPatrolRole", PolicyName="GDPatrol_lambda_policy"
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
    
    # Wait for the role to be fully propagated
    print("Waiting for IAM role to be fully propagated...")
    sleep(10)

    for region in regions:
        lmb = boto3.client("lambda", region_name=region)
        cw_events = boto3.client("events", region_name=region)
        gd = boto3.client("guardduty", region_name=region)
        if not gd.list_detectors()["DetectorIds"]:
            created_detector = gd.create_detector(Enable=True)
            print(f"Created GuardDuty detector: {created_detector['DetectorId']}")
        else:
            print(f"Detector already exists: {gd.list_detectors()['DetectorIds'][0]}")

        try:
            lmb.get_function(FunctionName="GDPatrol")
            lmb.delete_function(FunctionName="GDPatrol")
        except Exception:
            pass
        sleep(2)
        # Lambda bug: create function right after the
        # role deleted will cause AccessDeniedExceptionKMS error
        env_vars = {"DELETE_NACL_ENTRY_DRY_RUN": "False"}
        if slack_webhook_url:
            env_vars["SLACK_WEB_HOOK_URL"] = slack_webhook_url
        try:
            lambda_response = lmb.create_function(
                FunctionName="GDPatrol",
                Runtime="python3.12",
                Role=lambda_role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": open(zipped, "rb").read()},
                Timeout=300,
                MemorySize=128,
                Environment={"Variables": env_vars},
            )
        except Exception as e:
            if "InvalidParameterValueException" in str(e) and "cannot be assumed by Lambda" in str(e):
                print("Error: IAM role cannot be assumed by Lambda. This might be due to timing issues.")
                print("Please wait a few minutes and try again, or check that the role has the correct trust policy.")
                print(f"Role ARN: {lambda_role_arn}")
                raise
            else:
                raise
        target_arn = lambda_response["FunctionArn"]
        target_id = f"Id{randrange(10**11, 10**12)}"

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
        print(f"Successfully deployed the GDPatrol lambda function in region {region}.")

        # Create DynamoDB tables if not existed
        dynamodb_client = boto3.client("dynamodb")
        
        # Create main GDPatrol table
        try:
            response = dynamodb_client.create_table(
                AttributeDefinitions=[
                    {
                        "AttributeName": "network_acl_id",
                        "AttributeType": "S",
                    },
                    {
                        "AttributeName": "created_at",
                        "AttributeType": "S",
                    },
                ],
                KeySchema=[
                    {
                        "AttributeName": "network_acl_id",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "created_at",
                        "KeyType": "RANGE",
                    },
                ],
                BillingMode="PAY_PER_REQUEST",
                TableName="GDPatrol",
            )
            print("Created DynamoDB table: GDPatrol")
        except dynamodb_client.exceptions.ResourceInUseException:
            pass
        
        # Create lock table
        try:
            response = dynamodb_client.create_table(
                AttributeDefinitions=[
                    {
                        "AttributeName": "lock_id",
                        "AttributeType": "S",
                    },
                ],
                KeySchema=[
                    {
                        "AttributeName": "lock_id",
                        "KeyType": "HASH",
                    },
                ],
                BillingMode="PAY_PER_REQUEST",
                TableName="GDPatrol_lock",
            )
            print("Created DynamoDB table: GDPatrol_lock")
        except dynamodb_client.exceptions.ResourceInUseException:
            pass

    remove(zipped)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy GDPatrol Lambda function.")
    parser.add_argument(
        "--slack-webhook-url",
        type=str,
        help="Slack webhook URL to be set as an environment variable in the Lambda function.",
        required=False,
    )
    args = parser.parse_args()
    run(slack_webhook_url=args.slack_webhook_url)
