import argparse
import subprocess
import tempfile
from os import environ, remove
from pathlib import Path
from shutil import copy2, copytree, make_archive, rmtree
from time import sleep
import boto3

LAMBDA_RUNTIME = "python3.14"
LAMBDA_REQUIREMENTS = ["requests>=2.32.0"]


def build_function_zip() -> str:
    """Build the Lambda deployment zip with source + vendored dependencies.

    Uses uv to install linux-x86_64 wheels for LAMBDA_RUNTIME alongside the
    GDPatrol source, then zips the combined directory.
    """
    build_dir = Path(tempfile.mkdtemp(prefix="gdpatrol-build-"))
    src = Path("GDPatrol")
    for entry in src.iterdir():
        if entry.name == "__pycache__":
            continue
        dest = build_dir / entry.name
        if entry.is_dir():
            copytree(entry, dest)
        else:
            copy2(entry, dest)
    py_version = LAMBDA_RUNTIME.removeprefix("python")
    subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--target",
            str(build_dir),
            "--python-platform",
            "x86_64-manylinux2014",
            "--python-version",
            py_version,
            *LAMBDA_REQUIREMENTS,
        ],
        check=True,
    )
    for cache in build_dir.rglob("__pycache__"):
        rmtree(cache, ignore_errors=True)
    zipped = make_archive("GDPatrol", "zip", root_dir=str(build_dir))
    rmtree(build_dir, ignore_errors=True)
    return zipped


def run(slack_web_hook_url=None):
    regions = []
    ec2 = boto3.client("ec2")
    response = ec2.describe_regions()
    for i in response["Regions"]:
        regions.append(i["RegionName"])

    with open("role_policy.json") as rp:
        assume_role_policy = rp.read()
    zipped = build_function_zip()

    with open("lambda_policy.json") as lp:
        lambda_policy = lp.read()

    iam = boto3.client("iam")
    # get-or-create the role so already-deployed Lambdas in other regions that
    # reference it keep working during redeploy; put_role_policy is idempotent,
    # so it's safe to call whether the role is new or already existed.
    lambda_role_arn = None
    for response in iam.get_paginator("list_roles").paginate():
        for role in response["Roles"]:
            if role["RoleName"] == "GDPatrolRole":
                lambda_role_arn = role["Arn"]
                break
        if lambda_role_arn is not None:
            break

    if lambda_role_arn is None:
        created_role = iam.create_role(RoleName="GDPatrolRole", AssumeRolePolicyDocument=assume_role_policy)
        lambda_role_arn = created_role["Role"]["Arn"]

    iam.put_role_policy(
        RoleName="GDPatrolRole",
        PolicyName="GDPatrol_lambda_policy",
        PolicyDocument=lambda_policy,
    )

    # Pass the Slack webhook through to the function; without it the Lambda
    # logs "Error publishing message to Slack" and no notification is sent
    lambda_env = {"DELETE_NACL_ENTRY_DRY_RUN": "False"}
    slack_web_hook_url = slack_web_hook_url or environ.get("SLACK_WEB_HOOK_URL")
    if slack_web_hook_url:
        lambda_env["SLACK_WEB_HOOK_URL"] = slack_web_hook_url
    else:
        print("WARNING: SLACK_WEB_HOOK_URL is not set; Slack notifications will fail.")

    for region in regions:
        lmb = boto3.client("lambda", region_name=region)
        cw_events = boto3.client("events", region_name=region)
        gd = boto3.client("guardduty", region_name=region)
        if not gd.list_detectors()["DetectorIds"]:
            created_detector = gd.create_detector(Enable=True)
            print("Created GuardDuty detector: {}".format(created_detector["DetectorId"]))
        else:
            gd.update_detector(DetectorId=gd.list_detectors()["DetectorIds"][0], Enable=True)
            print("Detector already exists: {}".format(gd.list_detectors()["DetectorIds"][0]))

        sleep(7)  # Lambda bug: create function right after the role is created will cause AccessDeniedExceptionKMS error
        # A freshly created IAM role can take a while to propagate, and
        # create_function intermittently fails with "The role defined for the
        # function cannot be assumed by Lambda" until it does — retry with backoff.
        for attempt in range(5):
            try:
                lambda_response = lmb.create_function(
                    FunctionName="GDPatrol",
                    Runtime=LAMBDA_RUNTIME,
                    Role=lambda_role_arn,
                    Handler="lambda_function.lambda_handler",
                    Code={"ZipFile": open(zipped, "rb").read()},
                    Timeout=300,
                    MemorySize=128,
                    Environment={"Variables": lambda_env},
                )
                break
            except lmb.exceptions.ResourceConflictException:
                # The function already exists (e.g. a redeploy) — update it in place
                # instead of failing, so a stale function never blocks the deploy.
                lambda_response = lmb.update_function_code(
                    FunctionName="GDPatrol",
                    ZipFile=open(zipped, "rb").read(),
                )
                # update_function_code leaves the function InProgress for a few
                # seconds; update_function_configuration raises ResourceConflict
                # if called before it settles.
                lmb.get_waiter("function_updated").wait(FunctionName="GDPatrol")
                lmb.update_function_configuration(
                    FunctionName="GDPatrol",
                    Runtime=LAMBDA_RUNTIME,
                    Role=lambda_role_arn,
                    Handler="lambda_function.lambda_handler",
                    Timeout=300,
                    MemorySize=128,
                    Environment={"Variables": lambda_env},
                )
                break
            except lmb.exceptions.InvalidParameterValueException as e:
                if "cannot be assumed" not in str(e) or attempt == 4:
                    raise
                print("Role not yet assumable in region {}, retrying...".format(str(region)))
                sleep(10)
        target_arn = lambda_response["FunctionArn"]
        # Stable target Id so put_targets replaces the same target on each redeploy
        # instead of accumulating toward EventBridge's hard limit of 5 targets/rule.
        target_id = "GDPatrolTarget"

        created_rule = cw_events.put_rule(
            Name="GDPatrol",
            EventPattern='{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}',
        )
        cw_events.put_targets(
            Rule="GDPatrol",
            Targets=[{"Id": target_id, "Arn": target_arn, "InputPath": "$.detail"}],
        )

        # Stable StatementId so redeploys don't accumulate duplicate resource-policy
        # statements toward Lambda's policy-size limit.
        try:
            lmb.add_permission(
                FunctionName=lambda_response["FunctionName"],
                StatementId="GDPatrolEventBridgeInvoke",
                Action="lambda:InvokeFunction",
                Principal="events.amazonaws.com",
                SourceArn=created_rule["RuleArn"],
            )
        except lmb.exceptions.ResourceConflictException:
            # Permission already present from a prior deploy — idempotent.
            pass
        print("Successfully deployed the GDPatrol lambda function in region {}.".format(str(region)))

        # Create DynamoDB table if not existed
        dynamodb_client = boto3.client("dynamodb", region_name=region)
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
        except dynamodb_client.exceptions.ResourceInUseException:
            pass

        # Create the lock table used by blacklist_ip's acquire_lock/release_lock
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
        except dynamodb_client.exceptions.ResourceInUseException:
            pass

    remove(zipped)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy GDPatrol to all enabled regions")
    parser.add_argument(
        "--slack-webhook-url",
        default=None,
        help="Slack incoming webhook URL for notifications (falls back to the SLACK_WEB_HOOK_URL environment variable)",
    )
    args = parser.parse_args()
    run(slack_web_hook_url=args.slack_webhook_url)
