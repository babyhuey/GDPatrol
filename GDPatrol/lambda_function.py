import datetime
import json
import logging
import os
import time
import uuid
from inspect import stack
from socket import gaierror, gethostbyname
from typing import Any, Dict, List, Optional, Union
import requests
import ipaddress

import boto3

# Use uppercase for environment variable
slack_web_hook_url = os.environ.get("SLACK_WEB_HOOK_URL")

# Use environment variables for table names
GD_PATROL_TABLE = os.environ.get("GD_PATROL_TABLE", "GDPatrol")
GD_PATROL_LOCK_TABLE = os.environ.get("GD_PATROL_LOCK_TABLE", "GDPatrol_lock")

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize boto3 clients at the top of the script
ec2_client = boto3.client("ec2")
dynamodb_client = boto3.client("dynamodb")
bedrock_client = boto3.client("bedrock-runtime")

# Grabbing the current timestamp for the footer
ts = time.time()
st = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def enhance_message_with_claude(message_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhance the message using Claude Sonnet on AWS Bedrock.
    """
    try:
        prompt = f"""You are a security expert analyzing a GuardDuty finding. Please analyze this security alert and provide:
1. A clear, human-friendly explanation of what this alert means
2. The potential impact and severity of this threat
3. Specific recommendations for investigation and remediation
4. Any additional context that would be helpful for the security team

Here is the alert data:
{json.dumps(message_data, indent=2)}

Please format your response in a clear, structured way that would be helpful for a security team to understand and act upon."""

        response = bedrock_client.invoke_model(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            body=json.dumps(
                {
                    "prompt": prompt,
                    "max_tokens_to_sample": 1000,
                    "temperature": 0.7,
                    "top_p": 0.9,
                }
            ),
        )

        response_body = json.loads(response.get("body").read())
        enhanced_message = response_body.get("completion", "")

        # Add the enhanced message to the description
        message_data["attachments"][0]["fields"].append(
            {"title": "AI Analysis", "value": enhanced_message, "short": False}
        )

        return message_data
    except Exception as e:
        logger.error(f"Error enhancing message with Claude: {e}")
        return message_data


def publish_message(slack_web_hook_url: str, data: str) -> None:
    """Publish a message to Slack with AI-enhanced analysis."""
    try:
        enhanced_data = enhance_message_with_claude(json.loads(data))
        requests.post(slack_web_hook_url, data=json.dumps(enhanced_data), timeout=30)
    except Exception as e:
        logger.error(f"Error publishing message to Slack: {e}")


def create_network_acl_entry(ip_address: str, nacl_id: str, rule_number: int) -> None:
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


def delete_oldest_acl_entry(nacl_id: str) -> None:
    """
    Delete the oldest ACL entry for a given Network ACL ID.
    If DynamoDB is empty, fall back to enumerating actual NACL entries from AWS.
    """
    try:
        response = dynamodb_client.query(
            TableName=GD_PATROL_TABLE,
            KeyConditionExpression="#pk = :pk_value",
            ExpressionAttributeNames={"#pk": "network_acl_id"},
            ExpressionAttributeValues={":pk_value": {"S": nacl_id}},
        )
        items = response.get("Items", [])
        if not items:
            logger.warning(f"No entries found in DynamoDB for NACL {nacl_id}. Falling back to AWS NACL entries.")
            nacl = ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]
            # Only consider deny, ingress rules (Egress=False, RuleAction='deny')
            deny_rules = [rule for rule in nacl["Entries"] if not rule["Egress"] and rule["RuleAction"] == "deny"]
            if not deny_rules:
                logger.warning(f"No deny ingress rules found in NACL {nacl_id}. Nothing to delete.")
                return
            # Find the oldest by lowest rule number
            oldest_rule = min(deny_rules, key=lambda r: r["RuleNumber"])
            logger.info(f"Deleting fallback network_acl rule_number = {oldest_rule['RuleNumber']} for {nacl_id}")
            ec2_client.delete_network_acl_entry(
                Egress=False,
                DryRun=os.environ.get("DELETE_NACL_ENTRY_DRY_RUN", "False").lower() == "true",
                NetworkAclId=nacl_id,
                RuleNumber=oldest_rule["RuleNumber"],
            )
            logger.info(f"Deleted fallback network_acl rule_number = {oldest_rule['RuleNumber']} for {nacl_id}")
            return
        oldest_item = items[0]
        logger.info(
            f"Deleting network_acl rule_number = {oldest_item['rule_number']['S']} for {nacl_id}"
        )

        ec2_client.delete_network_acl_entry(
            Egress=False,
            DryRun=os.environ.get("DELETE_NACL_ENTRY_DRY_RUN", "False").lower() == "true",
            NetworkAclId=nacl_id,
            RuleNumber=int(oldest_item["rule_number"]["S"]),
        )

        dynamodb_client.delete_item(
            TableName=GD_PATROL_TABLE,
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
        # Do not raise here; just log the error and continue


def acquire_lock(
    lock_table_name: str, lock_id: str, max_retries: int = 5, retry_delay: int = 2, ttl_seconds: int = 60
) -> None:
    """
    Acquire a lock from a DynamoDB table. Adds a TTL to avoid deadlocks.
    """
    for attempt in range(max_retries):
        try:
            response = dynamodb_client.get_item(
                TableName=lock_table_name, Key={"lock_id": {"S": lock_id}}
            )
            if "Item" in response:
                # Check TTL
                timestamp = int(response["Item"].get("timestamp", {"S": "0"})["S"])
                if time.time() - timestamp > ttl_seconds:
                    # Stale lock, delete it
                    dynamodb_client.delete_item(
                        TableName=lock_table_name, Key={"lock_id": {"S": lock_id}}
                    )
                else:
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


def release_lock(lock_table_name: str, lock_id: str) -> None:
    """
    Release a lock in a DynamoDB table.
    """
    try:
        dynamodb_client.delete_item(
            TableName=lock_table_name, Key={"lock_id": {"S": lock_id}}
        )
    except Exception as e:
        logger.error(f"Error releasing lock: {e}")


def blacklist_ip(
    ip_address: str, lock_table_name: str = None, lock_id: str = None
) -> bool:
    """
    Blacklist an IP address by adding it to the network ACLs.
    """
    try:
        # Validate IP address
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            logger.error(f"Invalid IP address: {ip_address}")
            return False

        # Use env table names if not provided
        lock_table_name = lock_table_name or GD_PATROL_LOCK_TABLE
        # Make lock_id resource-specific
        lock_id = lock_id or f"lock-{ip_address}"
        acquire_lock(lock_table_name, lock_id)

        # Use paginator for NACLs
        paginator = ec2_client.get_paginator("describe_network_acls")
        nacls = []
        for page in paginator.paginate():
            nacls.extend(page["NetworkAcls"])

        for nacl in nacls:
            # Check if IP is already blacklisted in this NACL
            existing_rule = None
            for rule in nacl["Entries"]:
                if not rule["Egress"] and rule["RuleAction"] == "deny" and rule["CidrBlock"] == f"{ip_address}/32":
                    existing_rule = rule
                    break
            
            if existing_rule:
                logger.info(f"IP {ip_address} is already blacklisted in NACL {nacl['NetworkAclId']} with rule {existing_rule['RuleNumber']}")
                continue
                
            # Get all deny rules for this NACL
            deny_rules = [
                rule
                for rule in nacl["Entries"]
                if not rule["Egress"] and rule["RuleAction"] == "deny"
            ]

            # Check if we're approaching the limit (max 20 rules per direction)
            if len(deny_rules) >= 19:
                logger.warning(f"NACL {nacl['NetworkAclId']} has {len(deny_rules)} deny rules, approaching limit of 20")
                # Try to delete the oldest entry proactively
                try:
                    delete_oldest_acl_entry(nacl["NetworkAclId"])
                    logger.info(f"Proactively deleted oldest entry from NACL {nacl['NetworkAclId']}")
                except Exception as e:
                    logger.error(f"Failed to proactively delete oldest entry: {e}")
                    continue

            if not deny_rules:
                # If no deny rules exist, start with rule number 100
                target_rule_number = 100
            else:
                # Find the minimum rule number among deny rules
                min_rule_id = min(rule["RuleNumber"] for rule in deny_rules)
                # Ensure we don't create rules with numbers <= 1
                if min_rule_id <= 2:
                    logger.error(f"Rule number {min_rule_id} is too low to create new rules")
                    continue
                target_rule_number = min_rule_id - 1

            try:
                create_network_acl_entry(
                    ip_address, nacl["NetworkAclId"], target_rule_number
                )

                # Store the new entry in DynamoDB
                dynamodb_client.put_item(
                    TableName=GD_PATROL_TABLE,
                    Item={
                        "network_acl_id": {"S": nacl["NetworkAclId"]},
                        "created_at": {"S": str(time.time())},
                        "rule_number": {"S": str(target_rule_number)},
                    },
                )

                logger.info(f"Successfully blacklisted IP: {ip_address}")
                return True

            except Exception as error:
                logger.info(f"INFO: {error}")
                if "NetworkAclEntryLimitExceeded" in str(error):
                    try:
                        logger.info(f"Network ACL limit exceeded for {nacl['NetworkAclId']}, attempting to delete oldest entry")
                        delete_oldest_acl_entry(nacl["NetworkAclId"])
                        # Retry creating the entry after deleting the oldest one
                        create_network_acl_entry(
                            ip_address, nacl["NetworkAclId"], target_rule_number
                        )
                        # Store the new entry in DynamoDB
                        dynamodb_client.put_item(
                            TableName=GD_PATROL_TABLE,
                            Item={
                                "network_acl_id": {"S": nacl["NetworkAclId"]},
                                "created_at": {"S": str(time.time())},
                                "rule_number": {"S": str(target_rule_number)},
                            },
                        )
                        logger.info(
                            f"Successfully blacklisted IP: {ip_address} after deleting oldest entry"
                        )
                        return True
                    except Exception as retry_error:
                        logger.error(
                            f"Failed to create entry after deleting oldest: {retry_error}"
                        )
                        # Try the next NACL instead of continuing with the same one
                        break
                else:
                    logger.error(f"Error creating network_acl entry: {error}")
                    continue
    except Exception as e:
        logger.error(f"Error executing blacklist_ip: {e}")
        return False
    finally:
        release_lock(lock_table_name, lock_id)
    return False


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
    def __init__(self, finding_type: str) -> None:
        self.finding_type = finding_type
        with open("config.json") as f:
            self.config = json.load(f)

    def get_actions(self) -> List[str]:
        for playbook in self.config["playbooks"]["playbook"]:
            if playbook["type"] == self.finding_type:
                return (
                    playbook["actions"]
                    if isinstance(playbook["actions"], list)
                    else [playbook["actions"]]
                )
        return []

    def get_reliability(self) -> int:
        for playbook in self.config["playbooks"]["playbook"]:
            if playbook["type"] == self.finding_type:
                return playbook["reliability"]
        return 5


def lambda_handler(event: Dict[str, Any], context: Any) -> None:
    logger.info(f"GDPatrol: Received JSON event - {event}")
    try:
        finding_id = event.get("id")
        finding_type = event.get("type")
        if not finding_id or not finding_type:
            logger.error("Missing required fields in event: 'id' or 'type'")
            return
        logger.info(
            f"GDPatrol: Parsed Finding ID: {finding_id} - Finding Type: {finding_type}"
        )
        config = Config(event["type"])
        severity = int(event.get("severity", 0))
        count = event.get("service", {}).get("count", 0)

        config_actions = config.get_actions()
        config_reliability = config.get_reliability()
        resource_type = event.get("resource", {}).get("resourceType")
    except KeyError as e:
        logger.error(
            f"GDPatrol: Could not parse the Finding fields correctly, please verify that the JSON is correct. {e}"
        )
        return
    if resource_type == "Instance":
        instance = event["resource"]["instanceDetails"]
        instance_id = instance["instanceId"]
        vpc_id = instance["networkInterfaces"][0]["vpcId"]
    elif resource_type == "AccessKey":
        username = event["resource"]["accessKeyDetails"]["userName"]

    action_type = event.get("service", {}).get("action", {}).get("actionType")
    ip_address = None
    domain = None
    if action_type == "DNS_REQUEST":
        domain = event["service"]["action"]["dnsRequestAction"].get("domain")
    elif action_type == "AWS_API_CALL":
        ip_address = event["service"]["action"]["awsApiCallAction"].get("remoteIpDetails", {}).get("ipAddressV4")
    elif action_type == "NETWORK_CONNECTION":
        ip_address = event["service"]["action"]["networkConnectionAction"].get("remoteIpDetails", {}).get("ipAddressV4")
    elif action_type == "PORT_PROBE":
        port_probe_details = event["service"]["action"]["portProbeAction"].get("portProbeDetails", [])
        if port_probe_details:
            ip_address = port_probe_details[0].get("remoteIpDetails", {}).get("ipAddressV4")

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

    logger.info(f"GDPatrol: Executed {successful_actions}/{actions_to_be_executed} actions successfully.")

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
    if event_severity > 5:
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
