import datetime
import json
import logging
import time
import uuid
from inspect import stack
from socket import gaierror, gethostbyname

import boto3

import slack

slack_web_hook_url = (
    "https://hooks.slack.com/services/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"
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Grabbing the current timestamp for the footer
ts = time.time()
st = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def blacklist_ip(ip_address):
    import os
    try:
        client = boto3.client("ec2")
        dynamodb_client = boto3.client('dynamodb')
        nacls = client.describe_network_acls()
        for nacl in nacls["NetworkAcls"]:
            min_rule_id = min(
                rule["RuleNumber"] for rule in nacl["Entries"] if not rule["Egress"]
            )
            if min_rule_id < 1:
                raise Exception("Rule number is less than 1")
            target_rule_number = min_rule_id - 1
            # Add target rule_number to DynamoDB table
            dynamodb_client.put_item(
                TableName='GDPatrol', 
                Item={
                    'network_acl_id' :{'S': nacl["NetworkAclId"]},
                    'created_at': {'S': str(ts)},
                    'rule_number': {'S': str(target_rule_number)}
                }
            )

            # Add ip_address to entry nacl
            try:
                r = client.create_network_acl_entry(
                    CidrBlock=f"{ip_address}/32",
                    Egress=False,
                    NetworkAclId=nacl["NetworkAclId"],
                    Protocol="-1",
                    RuleAction="deny",
                    RuleNumber=target_rule_number,
                )
                logger.info(f"created network_acl rule_number = {target_rule_number}")
            except Exception:
                response = dynamodb_client.query(
                    TableName="GDPatrol",
                    KeyConditionExpression='#pk = :pk_value',
                    ExpressionAttributeNames={'#pk': 'network_acl_id'},
                    ExpressionAttributeValues={':pk_value': {'S': nacl["NetworkAclId"]}}
                )
                oldest_item = response["Items"][0]
                try:
                    dynamodb_client.delete_item(
                        TableName="GDPatrol",
                        Key={
                            'network_acl_id': oldest_item["network_acl_id"], 
                            'created_at': oldest_item["created_at"]
                        }
                    )
                except Exception as e:
                    logger.error(f"can't delete the item from table: {e}")

                logger.info(f"deleting network_acl rule_number = {oldest_item['rule_number']['S']}")
                client.delete_network_acl_entry(
                    Egress=False,
                    DryRun=eval(os.environ['DELETE_NACL_ENTRY_DRY_RUN']),
                    NetworkAclId=nacl["NetworkAclId"],
                    RuleNumber=int(oldest_item["rule_number"]['S'])
                )
                logger.info(f"deleted network_acl rule_number = {oldest_item['rule_number']['S']}")
                client.create_network_acl_entry(
                    CidrBlock=f"{ip_address}/32",
                    Egress=False,
                    NetworkAclId=nacl["NetworkAclId"],
                    Protocol="-1",
                    RuleAction="deny",
                    RuleNumber=target_rule_number,
                )
                logger.info(f"created network_acl rule_number = {target_rule_number}")
                
            logger.info(
                "GDPatrol: Successfully executed action {} for ".format(
                    stack()[0][3], ip_address
                )
            )
        return True
    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")


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
            "GDPatrol: Successfully executed action {} for {}".format(
                stack()[0][3], ip_address
            )
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
            "GDPatrol: Successfully executed action {} for {}".format(
                stack()[0][3], instance_id
            )
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
            snapshot = client.create_snapshot(
                VolumeId=device["Ebs"]["VolumeId"],
                Description=f"Created by GDpatrol for {instance_id}",
            )
        logger.info(
            "GDPatrol: Successfully executed action {} for {}".format(
                stack()[0][3], instance_id
            )
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
            "GDPatrol: Successfully executed action {} for {}".format(
                stack()[0][3], username
            )
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
            "GDPatrol: Successfully executed action {} for {}".format(
                stack()[0][3], username
            )
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
            "GDPatrol: Successfully executed action {} for {}".format(
                stack()[0][3], username
            )
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
            "GDPatrol: Successfully executed action {} for {}".format(
                stack()[0][3], username
            )
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
            "GDPatrol: Successfully executed action {} for {}".format(
                stack()[0][3], username
            )
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
            "GDPatrol: Successfully executed action {} for {}".format(
                stack()[0][3], instance_id
            )
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
            "GDPatrol: Parsed Finding ID: {} - Finding Type: {}".format(
                finding_id, finding_type
            )
        )
        config = Config(event["type"])
        severity = int(event["severity"])
        count = event["service"]["count"]

        config_actions = config.get_actions()
        config_reliability = config.get_reliability()
        resource_type = event["resource"]["resourceType"]
    except KeyError as e:
        logger.error(
            "GDPatrol: Could not parse the Finding fields correctly, please verify that the JSON is correct"
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
    event_id = event["id"]

    # Adding link to finding in the description
    event_description += "GDPatrol: Total actions: {} - Actions to be executed: {} - Successful Actions: {} - Finding ID:  {} - Finding Type: {}".format(
        total_config_actions,
        actions_to_be_executed,
        successful_actions,
        finding_id,
        finding_type,
    )

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
        slack.publish_message(slack_web_hook_url, json.dumps(guardduty_finding))
    logger.info(
        "GDPatrol: Total actions: {} - Actions to be executed: {} - Successful Actions: {} - Finding ID:  {} - Finding Type: {}".format(
            total_config_actions,
            actions_to_be_executed,
            successful_actions,
            finding_id,
            finding_type,
        )
    )
