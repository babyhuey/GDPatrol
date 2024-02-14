import datetime
import json
import logging
import os
import time
import uuid
from inspect import stack
from socket import gaierror, gethostbyname
import requests

import boto3

slack_web_hook_url = (
    "https://hooks.slack.com/services/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"
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize boto3 clients at the top of the script
ec2_client = boto3.client("ec2")
dynamodb_client = boto3.client("dynamodb")

# Grabbing the current timestamp for the footer
ts = time.time()
st = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def publish_message(slack_web_hook_url, data):
    requests.post(slack_web_hook_url, data=data, timeout=30)


def create_network_acl_entry(ip_address, nacl_id, rule_number):
    """
    Create a network ACL entry to block the specified IP address.
    """
    try:
        ec2_client.create_network_acl_entry(
            CidrBlock=f"{ip_address}/32",
            Egress=False,
            NetworkAclId=nacl_id,
            Protocol="-1",
            RuleAction="deny",
            RuleNumber=rule_number,
        )
        logger.info(f"Created network_acl rule_number = {rule_number} for {nacl_id}")
    except Exception as error:
        logger.error(f"Error creating network_acl entry: {error}")
        raise


def delete_oldest_acl_entry(nacl_id):
    """
    Delete the oldest ACL entry for a given Network ACL ID.
    """
    try:
        response = dynamodb_client.query(
            TableName="GDPatrol",
            KeyConditionExpression="#pk = :pk_value",
            ExpressionAttributeNames={"#pk": "network_acl_id"},
            ExpressionAttributeValues={":pk_value": {"S": nacl_id}},
        )
        oldest_item = response["Items"][0]
        logger.info(
            f"Deleting network_acl rule_number = {oldest_item['rule_number']['S']} for {nacl_id}"
        )

        ec2_client.delete_network_acl_entry(
            Egress=False,
            DryRun=eval(os.environ.get("DELETE_NACL_ENTRY_DRY_RUN", "False")),
            NetworkAclId=nacl_id,
            RuleNumber=int(oldest_item["rule_number"]["S"]),
        )

        dynamodb_client.delete_item(
            TableName="GDPatrol",
            Key={
                "network_acl_id": {"S": nacl_id},
                "created_at": {"S": oldest_item["created_at"]["S"]},
            },
        )
        logger.info(
            f"Deleted network_acl rule_number = {oldest_item['rule_number']['S']} for {nacl_id}"
        )
    except Exception as error:
        logger.error(f"Error deleting the oldest ACL entry: {error}")
        raise


def acquire_lock(lock_table_name, lock_id, max_retries=5, retry_delay=2):
    """
    Acquire a lock from a DynamoDB table.
    """
    for attempt in range(max_retries):
        try:
            response = dynamodb_client.get_item(
                TableName=lock_table_name, Key={"lock_id": {"S": lock_id}}
            )
            if "Item" in response:
                time.sleep(retry_delay)
                continue

            dynamodb_client.put_item(
                TableName=lock_table_name,
                Item={
                    "lock_id": {"S": lock_id},
                    "timestamp": {"S": str(int(time.time()))},
                },
                ConditionExpression="attribute_not_exists(lock_id)",
            )
            return
        except dynamodb_client.exceptions.ConditionalCheckFailedException:
            time.sleep(retry_delay)

    raise Exception("Unable to acquire lock after multiple attempts")


def release_lock(lock_table_name, lock_id):
    """
    Release a lock in a DynamoDB table.
    """
    dynamodb_client.delete_item(
        TableName=lock_table_name, Key={"lock_id": {"S": lock_id}}
    )


def blacklist_ip(ip_address, lock_table_name="GDPatrol_lock", lock_id="lock"):
    """
    Blacklist an IP address by adding it to the network ACLs.
    """
    try:
        acquire_lock(lock_table_name, lock_id)
        nacls = ec2_client.describe_network_acls()

        for nacl in nacls["NetworkAcls"]:
            min_rule_id = min(
                rule["RuleNumber"]
                for rule in nacl["Entries"]
                if not rule["Egress"] and rule["RuleAction"] == "deny"
            )
            if min_rule_id <= 1:
                logger.error("Rule number is less than or equal to 1")
                continue

            target_rule_number = min_rule_id - 1
            try:
                create_network_acl_entry(
                    ip_address, nacl["NetworkAclId"], target_rule_number
                )
            except Exception as error:
                logger.info(f"INFO: {error}")
                if "NetworkAclEntryLimitExceeded" in str(error):
                    delete_oldest_acl_entry(nacl["NetworkAclId"])
                continue

            logger.info(f"Successfully blacklisted IP: {ip_address}")
            break
    except Exception as e:
        logger.error(f"Error executing blacklist_ip: {e}")
        return False
    finally:
        release_lock(lock_table_name, lock_id)
    return True


def whitelist_ip(ip_address):
    try:
        client = boto3.client("ec2")
        nacls = client.describe_network_acls()
        for nacl in nacls["NetworkAcls"]:
            for rule in nacl["Entries"]:
                if rule["CidrBlock"] == f"{ip_address}/32":
                    client.delete_network_acl_entry(
                        NetworkAclId=nacl["NetworkAclId"],
                        Egress=rule["Egress"],
                        RuleNumber=rule["RuleNumber"],
                    )
        logger.info(
            f"GDPatrol: Successfully executed action {stack()[0][3]} for {ip_address}"
        )
        return True

    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False


def quarantine_instance(instance_id, vpc_id):
    try:
        client = boto3.client("ec2")
        sg = client.create_security_group(
            GroupName=f"Quarantine-{str(uuid.uuid4().fields[-1])[:6]}",
            Description=f"Quarantine for {instance_id}",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        # NOTE: Remove the default egress group
        client.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "FromPort": 0,
                    "ToPort": 65535,
                    "IpRanges": [
                        {"CidrIp": "0.0.0.0/0"},
                    ],
                }
            ],
        )

        # NOTE: Assign security group to instance
        client.modify_instance_attribute(InstanceId=instance_id, Groups=[sg_id])

        logger.info(
            f"GDPatrol: Successfully executed action {stack()[0][3]} for {instance_id}"
        )
        return True
    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False


def snapshot_instance(instance_id):
    try:
        client = boto3.client("ec2")
        instance_described = client.describe_instances(InstanceIds=[instance_id])
        blockmappings = instance_described["Reservations"][0]["Instances"][0][
            "BlockDeviceMappings"
        ]
        for device in blockmappings:
            client.create_snapshot(
                VolumeId=device["Ebs"]["VolumeId"],
                Description=f"Created by GDpatrol for {instance_id}",
            )
        logger.info(
            f"GDPatrol: Successfully executed action {stack()[0][3]} for {instance_id}"
        )
        return True
    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False


def disable_account(username):
    try:
        client = boto3.client("iam")
        client.put_user_policy(
            UserName=username,
            PolicyName="BlockAllPolicy",
            PolicyDocument='{"Version":"2012-10-17", "Statement"'
            ':{"Effect":"Deny", "Action":"*", '
            '"Resource":"*"}}',
        )
        logger.info(
            f"GDPatrol: Successfully executed action {stack()[0][3]} for {username}"
        )
        return True
    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False


def disable_ec2_access(username):
    try:
        client = boto3.client("iam")
        client.put_user_policy(
            UserName=username,
            PolicyName="BlockEC2Policy",
            PolicyDocument='{"Version":"2012-10-17", "Statement"'
            ':{"Effect":"Deny", "Action":"ec2:*" , '
            '"Resource":"*"}}',
        )
        logger.info(
            f"GDPatrol: Successfully executed action {stack()[0][3]} for {username}"
        )
        return True
    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False


def enable_ec2_access(username):
    try:
        client = boto3.client("iam")
        client.delete_user_policy(
            UserName=username,
            PolicyName="BlockEC2Policy",
        )
        logger.info(
            f"GDPatrol: Successfully executed action {stack()[0][3]} for {username}"
        )
        return True
    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False


def disable_sg_access(username):
    try:
        client = boto3.client("iam")
        client.put_user_policy(
            UserName=username,
            PolicyName="BlockSecurityGroupPolicy",
            PolicyDocument='{"Version":"2012-10-17", "Statement"'
            ':{"Effect":"Deny", "Action": [ '
            '"ec2:AuthorizeSecurityGroupIngress", '
            '"ec2:RevokeSecurityGroupIngress", '
            '"ec2:AuthorizeSecurityGroupEgress", '
            '"ec2:RevokeSecurityGroupEgress" ], '
            '"Resource":"*"}}',
        )
        logger.info(
            f"GDPatrol: Successfully executed action {stack()[0][3]} for {username}"
        )
        return True
    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False


def enable_sg_access(username):
    try:
        client = boto3.client("iam")
        client.delete_user_policy(
            UserName=username,
            PolicyName="BlockSecurityGroupPolicy",
        )
        logger.info(
            f"GDPatrol: Successfully executed action {stack()[0][3]} for {username}"
        )
        return True
    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False


def asg_detach_instance(instance_id):
    try:
        client = boto3.client("autoscaling")
        response = client.describe_auto_scaling_instances(
            InstanceIds=[instance_id], MaxRecords=1
        )
        asg_name = None
        instances = response["AutoScalingInstances"]
        if instances:
            asg_name = instances[0]["AutoScalingGroupName"]

        if asg_name is not None:
            response = client.detach_instances(
                InstanceIds=[instance_id],
                AutoScalingGroupName=asg_name,
                ShouldDecrementDesiredCapacity=False,
            )
        logger.info(
            f"GDPatrol: Successfully executed action {stack()[0][3]} for {instance_id}"
        )
        return True
    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False


class Config:
    def __init__(self, finding_type):
        self.finding_type = finding_type
        self.actions = []
        self.reliability = 0

    def get_actions(self):
        with open("config.json") as config:
            jsonloads = json.loads(config.read())
            for item in jsonloads["playbooks"]["playbook"]:
                if item["type"] == self.finding_type:
                    self.actions = item["actions"]
                    return self.actions

    def get_reliability(self):
        with open("config.json") as config:
            jsonloads = json.loads(config.read())
            for item in jsonloads["playbooks"]["playbook"]:
                if item["type"] == self.finding_type:
                    self.reliability = int(item["reliability"])
                    return self.reliability


def lambda_handler(event, context):
    logger.info(f"GDPatrol: Received JSON event - {event}")
    try:

        finding_id = event["id"]
        finding_type = event["type"]
        logger.info(
            f"GDPatrol: Parsed Finding ID: {finding_id} - Finding Type: {finding_type}"
        )
        config = Config(event["type"])
        severity = int(event["severity"])
        count = event["service"]["count"]

        config_actions = config.get_actions()
        config_reliability = config.get_reliability()
        resource_type = event["resource"]["resourceType"]
    except KeyError as e:
        logger.error(
            f"GDPatrol: Could not parse the Finding fields correctly, please verify that the JSON is correct. {e}"
        )
        exit(1)
    if resource_type == "Instance":
        instance = event["resource"]["instanceDetails"]
        instance_id = instance["instanceId"]
        vpc_id = instance["networkInterfaces"][0]["vpcId"]
    elif resource_type == "AccessKey":
        username = event["resource"]["accessKeyDetails"]["userName"]

    if event["service"]["action"]["actionType"] == "DNS_REQUEST":
        domain = event["service"]["action"]["dnsRequestAction"]["domain"]
    elif event["service"]["action"]["actionType"] == "AWS_API_CALL":
        ip_address = event["service"]["action"]["awsApiCallAction"]["remoteIpDetails"][
            "ipAddressV4"
        ]
    elif event["service"]["action"]["actionType"] == "NETWORK_CONNECTION":
        ip_address = event["service"]["action"]["networkConnectionAction"][
            "remoteIpDetails"
        ]["ipAddressV4"]
    elif event["service"]["action"]["actionType"] == "PORT_PROBE":
        ip_address = event["service"]["action"]["portProbeAction"]["portProbeDetails"][
            0
        ]["remoteIpDetails"]["ipAddressV4"]

    successful_actions = 0
    total_config_actions = len(config_actions)
    actions_to_be_executed = 0
    for action in config_actions:
        logger.info(f"GDPatrol: Action: {action}")
        if action == "blacklist_ip":
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info(f"GDPatrol: Executing action {action}")
                result = blacklist_ip(ip_address)
                successful_actions += int(result)
            elif count > 100:
                actions_to_be_executed += 1
                logger.info(f"GDPatrol: Executing action {action}")
                result = blacklist_ip(ip_address)
                successful_actions += int(result)
        elif action == "whitelist_ip":
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info(f"GDPatrol: Executing action {action}")
                result = whitelist_ip(ip_address)
                successful_actions += int(result)
        elif action == "blacklist_domain":
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info(f"GDPatrol: Executing action {action}")
                try:
                    ip_address = gethostbyname(domain)
                    result = blacklist_ip(ip_address)
                    successful_actions += int(result)
                except gaierror as e:
                    logger.error(f"GDPatrol: Error resolving domain {domain} - {e}")
        elif action == "quarantine_instance":
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info(f"GDPatrol: Executing action {action}")
                result = quarantine_instance(instance_id, vpc_id)
                successful_actions += int(result)
        elif action == "snapshot_instance":
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info(f"GDPatrol: Executing action {action}")
                result = snapshot_instance(instance_id)
                successful_actions += int(result)
        elif action == "disable_account":
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info(f"GDPatrol: Executing action {action}")
                result = disable_account(username)
                successful_actions += int(result)
        elif action == "disable_ec2_access":
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info(f"GDPatrol: Executing action {action}")
                result = disable_ec2_access(username)
                successful_actions += int(result)
        elif action == "enable_ec2_access":
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info(f"GDPatrol: Executing action {action}")
                result = enable_ec2_access(username)
                successful_actions += int(result)
        elif action == "disable_sg_access":
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info(f"GDPatrol: Executing action {action}")
                result = disable_sg_access(username)
                successful_actions += int(result)
        elif action == "enable_sg_access":
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info(f"GDPatrol: Executing action {action}")
                result = enable_sg_access(username)
                successful_actions += int(result)
        elif action == "asg_detach_instance":
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info(f"GDPatrol: Executing action {action}")
                result = asg_detach_instance(instance_id)
                successful_actions += int(result)

    event_description = event["description"]
    event_account = event["accountId"]
    event_region = event["region"]
    event_severity = event["severity"]
    event_count = event["service"]["count"]
    event_first_seen = event["service"]["eventFirstSeen"]
    event_last_seen = event["service"]["eventLastSeen"]
    event_type = event["type"]
    # event_id = event["id"]

    # Adding link to finding in the description
    event_description += f"GDPatrol: Total actions: {total_config_actions} - Actions to be executed: {actions_to_be_executed} - Successful Actions: {successful_actions} - Finding ID:  {finding_id} - Finding Type: {finding_type}"

    guardduty_finding = {
        "attachments": [
            {
                "fallback": "GuardDuty Finding",
                "color": "#7e57c2",
                "title": "New GuardDuty Finding",
                "footer": "Alert generated at " + str(st),
                "fields": [
                    {"title": "Region", "value": event_region, "short": "true"},
                    {"title": "Account", "value": event_account, "short": "true"},
                    {"title": "Finding Type", "value": event_type, "short": "true"},
                    {
                        "title": "Event First Seen",
                        "value": event_first_seen,
                        "short": "true",
                    },
                    {
                        "title": "Event Last Seen",
                        "value": event_last_seen,
                        "short": "true",
                    },
                    {"title": "Severity", "value": event_severity, "short": "true"},
                    {"title": "Count", "value": event_count, "short": "true"},
                    {"title": "Description", "value": event_description},
                ],
            }
        ]
    }
    # slack.slack_post(event)
    if event_severity >= 5:
        publish_message(slack_web_hook_url, json.dumps(guardduty_finding))
    logger.info(
        f"GDPatrol: Total actions: {total_config_actions} - Actions to be executed: {actions_to_be_executed} - Successful Actions: {successful_actions} - Finding ID:  {finding_id} - Finding Type: {finding_type}"
    )


def create_lock_table():
    dynamodb = boto3.resource("dynamodb")
    table_name = "GDPatrol_lock"

    # Check if the table already exists
    try:
        table = dynamodb.Table(table_name)
        if table.table_status not in ["CREATING", "UPDATING", "DELETING", "ACTIVE"]:
            return
        logger.info(f"Table '{table_name}' already exists.")
    except dynamodb.meta.client.exceptions.ResourceNotFoundException:
        pass  # Table does not exist, proceed with creation

    # Create the table
    table = dynamodb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "lock_id", "KeyType": "HASH"}],  # Partition key
        AttributeDefinitions=[
            {"AttributeName": "lock_id", "AttributeType": "S"}  # String
        ],
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
    )

    # Wait until the table exists, this will block until the table is created
    table.meta.client.get_waiter("table_exists").wait(TableName=table_name)
    logger.info(f"Table '{table_name}' created successfully.")
