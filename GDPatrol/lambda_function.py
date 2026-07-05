import datetime
import json
import logging
import os
import time
import uuid
import socket
from inspect import stack
from typing import Any, Dict, List
import requests
import ipaddress

import boto3
from botocore.exceptions import ClientError

# Use uppercase for environment variable
slack_web_hook_url = os.environ.get("SLACK_WEB_HOOK_URL")

# Use environment variables for table names
GD_PATROL_TABLE = os.environ.get("GD_PATROL_TABLE", "GDPatrol")
GD_PATROL_LOCK_TABLE = os.environ.get("GD_PATROL_LOCK_TABLE", "GDPatrol_lock")
# All NACL-mutating actions serialize on this single lock id, since blacklist_ip/whitelist_ip
# each mutate every NACL in the account rather than just one keyed by IP.
GD_PATROL_NACL_LOCK_ID = "gdpatrol-nacl"

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize boto3 clients at the top of the script
ec2_client = boto3.client("ec2")
dynamodb_client = boto3.client("dynamodb")
bedrock_client = boto3.client("bedrock-runtime")


def summarize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Extract security-relevant fields from a GuardDuty event."""
    summary: Dict[str, Any] = {
        "finding_type": event.get("type"),
        "severity": event.get("severity"),
        "description": event.get("description"),
        "region": event.get("region"),
        "account": event.get("accountId"),
    }

    # Who / source
    service = event.get("service", {})
    action = service.get("action", {})
    action_type = action.get("actionType")
    summary["action_type"] = action_type

    if action_type == "AWS_API_CALL":
        api_action = action.get("awsApiCallAction", {})
        summary["source_ip"] = api_action.get("remoteIpDetails", {}).get("ipAddressV4")
        summary["api_call"] = api_action.get("api")
        summary["service_name"] = api_action.get("serviceName")
        summary["caller_type"] = api_action.get("callerType")
    elif action_type == "NETWORK_CONNECTION":
        net_action = action.get("networkConnectionAction", {})
        summary["source_ip"] = net_action.get("remoteIpDetails", {}).get("ipAddressV4")
        summary["direction"] = net_action.get("connectionDirection")
        summary["protocol"] = net_action.get("protocol")
        summary["local_port"] = net_action.get("localPortDetails", {}).get("port")
        summary["remote_port"] = net_action.get("remotePortDetails", {}).get("port")
    elif action_type == "DNS_REQUEST":
        summary["domain"] = action.get("dnsRequestAction", {}).get("domain")
    elif action_type == "PORT_PROBE":
        probes = action.get("portProbeAction", {}).get("portProbeDetails", [])
        if probes:
            summary["source_ip"] = probes[0].get("remoteIpDetails", {}).get("ipAddressV4")
            summary["probed_port"] = probes[0].get("localPortDetails", {}).get("port")
    elif action_type == "RDS_LOGIN_ATTEMPT":
        rds_action = action.get("rdsLoginAttemptAction", {})
        summary["source_ip"] = rds_action.get("remoteIpDetails", {}).get("ipAddressV4")

    # Target resource
    resource = event.get("resource", {})
    resource_type = resource.get("resourceType")
    summary["resource_type"] = resource_type
    if resource_type == "Instance":
        details = resource.get("instanceDetails", {})
        summary["instance_id"] = details.get("instanceId")
        summary["instance_type"] = details.get("instanceType")
        tags = {t["key"]: t["value"] for t in details.get("tags", []) if "key" in t}
        if "Name" in tags:
            summary["instance_name"] = tags["Name"]
    elif resource_type == "AccessKey":
        details = resource.get("accessKeyDetails", {})
        summary["username"] = details.get("userName")
        summary["principal_id"] = details.get("principalId")
    elif resource_type == "RDSDBInstance":
        details = resource.get("rdsDbInstanceDetails", {})
        summary["db_instance"] = details.get("dbInstanceIdentifier")
        summary["db_engine"] = details.get("engine")

    # Remove None values for cleanliness
    return {k: v for k, v in summary.items() if v is not None}


def enhance_message_with_claude(message_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhance the message using Claude Sonnet on AWS Bedrock.
    """
    try:
        prompt = f"""You are a security expert analyzing a GuardDuty finding. Provide a concise analysis:
1. What this alert means in plain language
2. Potential impact and severity
3. Recommended investigation and remediation steps

Alert data:
{json.dumps(message_data, indent=2)}

Be concise — this will appear in a Slack message attachment. Format the response as Slack mrkdwn, \
NOT standard Markdown: *single asterisks* for bold, _underscores_ for italic, hyphen bullets. \
Slack has no heading syntax — use a short bold line instead of ## headings."""

        response = bedrock_client.invoke_model(
            # On-demand invocation requires an inference profile ID, not the bare model ID
            modelId="global.anthropic.claude-sonnet-4-6",
            body=json.dumps(
                {
                    "anthropic_version": "bedrock-2023-05-31",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1000,
                    # Claude 4.x rejects requests that set both temperature and top_p
                    "temperature": 0.7,
                }
            ),
        )

        response_body = json.loads(response.get("body").read())
        enhanced_message = response_body["content"][0]["text"]

        # Add the enhanced message to the description
        message_data["attachments"][0]["fields"].append({"title": "AI Analysis", "value": enhanced_message, "short": False})

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


def _next_free_ingress_deny_rule_number(entries: List[Dict[str, Any]]) -> int | None:
    """
    Return an unused ingress rule number for a new ingress deny rule, or None if the NACL
    has no free ingress rule numbers left.

    Considers ALL ingress entries (allow and deny) so the result never collides with a
    pre-existing rule — ingress and egress rule numbers are independent namespaces, so
    egress entries are ignored.

    Preference order: one below the current lowest GDPatrol deny rule (the existing
    decrement scheme), or the next free number below that. If the low end (near 1) is
    exhausted, search downward from the high end (32766; 32767 is the implicit default-deny)
    instead of evicting whoever holds a fixed slot.
    """
    used = {entry["RuleNumber"] for entry in entries if not entry["Egress"]}
    deny_numbers = [entry["RuleNumber"] for entry in entries if not entry["Egress"] and entry["RuleAction"] == "deny"]
    start = (min(deny_numbers) - 1) if deny_numbers else 100

    candidate = start
    while candidate >= 1:
        if candidate not in used:
            return candidate
        candidate -= 1

    # Low end exhausted (or fully occupied); search down from the high end instead.
    candidate = 32766
    floor = max(start, 0)
    while candidate > floor:
        if candidate not in used:
            return candidate
        candidate -= 1

    return None


def _create_and_track_deny_rule(ip_address: str, nacl_id: str, rule_number: int) -> None:
    """Create the deny rule in AWS and record it in DynamoDB so it can be found again as "oldest"."""
    create_network_acl_entry(ip_address, nacl_id, rule_number)
    dynamodb_client.put_item(
        TableName=GD_PATROL_TABLE,
        Item={
            "network_acl_id": {"S": nacl_id},
            "created_at": {"S": str(time.time())},
            "rule_number": {"S": str(rule_number)},
        },
    )


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
            # Only consider GDPatrol-managed rules: ingress deny rules with a /32 CidrBlock.
            # This excludes the implicit default-deny (0.0.0.0/0 @ 32767) and customer subnet-level denies.
            deny_rules = [
                rule
                for rule in nacl["Entries"]
                if not rule["Egress"] and rule["RuleAction"] == "deny" and rule.get("CidrBlock", "").endswith("/32")
            ]
            if not deny_rules:
                logger.warning(f"No GDPatrol-managed deny ingress rules found in NACL {nacl_id}. Nothing to delete.")
                return
            # New rules get decreasing numbers, so the HIGHEST rule number is the oldest.
            oldest_rule = max(deny_rules, key=lambda r: r["RuleNumber"])
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
        logger.info(f"Deleting network_acl rule_number = {oldest_item['rule_number']['S']} for {nacl_id}")

        try:
            ec2_client.delete_network_acl_entry(
                Egress=False,
                DryRun=os.environ.get("DELETE_NACL_ENTRY_DRY_RUN", "False").lower() == "true",
                NetworkAclId=nacl_id,
                RuleNumber=int(oldest_item["rule_number"]["S"]),
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "InvalidNetworkAclEntry.NotFound":
                raise
            # AWS and DynamoDB have drifted apart; reconcile by removing the stale tracking row below,
            # instead of leaving it to be returned as "oldest" forever.
            logger.warning(f"Rule {oldest_item['rule_number']['S']} not found in NACL {nacl_id}; reconciling stale DynamoDB row.")

        dynamodb_client.delete_item(
            TableName=GD_PATROL_TABLE,
            Key={
                "network_acl_id": {"S": nacl_id},
                "created_at": {"S": oldest_item["created_at"]["S"]},
            },
        )
        logger.info(f"Deleted network_acl rule_number = {oldest_item['rule_number']['S']} for {nacl_id}")
    except Exception as error:
        logger.error(f"Error deleting the oldest ACL entry: {error}")
        # Do not raise here; just log the error and continue


def acquire_lock(lock_table_name: str, lock_id: str, max_retries: int = 60, retry_delay: int = 3, ttl_seconds: int = 60) -> None:
    """
    Acquire a lock from a DynamoDB table. Adds a TTL to avoid deadlocks.
    """
    for attempt in range(max_retries):
        try:
            response = dynamodb_client.get_item(TableName=lock_table_name, Key={"lock_id": {"S": lock_id}})
            if "Item" in response:
                # Check TTL
                timestamp = int(response["Item"].get("timestamp", {"S": "0"})["S"])
                if time.time() - timestamp > ttl_seconds:
                    # Stale lock, delete it
                    dynamodb_client.delete_item(TableName=lock_table_name, Key={"lock_id": {"S": lock_id}})
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
        dynamodb_client.delete_item(TableName=lock_table_name, Key={"lock_id": {"S": lock_id}})
    except Exception as e:
        logger.error(f"Error releasing lock: {e}")


def delete_dynamodb_rule_entries(nacl_id: str, rule_numbers: set) -> None:
    """
    Remove the DynamoDB entries tracking NACL rules that no longer exist in AWS,
    so the table doesn't drift from the actual NACL state.
    """
    if not rule_numbers:
        return
    try:
        response = dynamodb_client.query(
            TableName=GD_PATROL_TABLE,
            KeyConditionExpression="#pk = :pk_value",
            ExpressionAttributeNames={"#pk": "network_acl_id"},
            ExpressionAttributeValues={":pk_value": {"S": nacl_id}},
        )
        for item in response.get("Items", []):
            if int(item["rule_number"]["S"]) in rule_numbers:
                dynamodb_client.delete_item(
                    TableName=GD_PATROL_TABLE,
                    Key={
                        "network_acl_id": {"S": nacl_id},
                        "created_at": {"S": item["created_at"]["S"]},
                    },
                )
    except Exception as e:
        logger.error(f"Error cleaning up DynamoDB entries for NACL {nacl_id}: {e}")


def blacklist_ip(ip_address: str, lock_table_name: str = None, lock_id: str = None) -> bool:
    """
    Blacklist an IP address by adding a deny rule to every network ACL.
    Returns True only if the IP is blocked in all NACLs.
    """
    # Validate IP address
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        logger.error(f"Invalid IP address: {ip_address}")
        return False

    # Use env table names if not provided
    lock_table_name = lock_table_name or GD_PATROL_LOCK_TABLE
    # A single fixed lock id, since this function mutates every NACL in the account,
    # not just resources related to ip_address.
    lock_id = lock_id or GD_PATROL_NACL_LOCK_ID
    lock_acquired = False
    try:
        acquire_lock(lock_table_name, lock_id)
        lock_acquired = True

        # Use paginator for NACLs
        paginator = ec2_client.get_paginator("describe_network_acls")
        nacls = []
        for page in paginator.paginate():
            nacls.extend(page["NetworkAcls"])

        blocked_count = 0
        for nacl in nacls:
            # Check if IP is already blacklisted in this NACL
            existing_rule = None
            for rule in nacl["Entries"]:
                if not rule["Egress"] and rule["RuleAction"] == "deny" and rule.get("CidrBlock") == f"{ip_address}/32":
                    existing_rule = rule
                    break

            if existing_rule:
                logger.info(
                    f"IP {ip_address} is already blacklisted in NACL {nacl['NetworkAclId']} with rule {existing_rule['RuleNumber']}"
                )
                blocked_count += 1
                continue

            # Get all deny rules for this NACL. Only GDPatrol-managed rules (ingress deny with a
            # /32 CidrBlock) count toward the threshold and are eligible for cleanup — this must
            # never sweep up a customer's own deny rule (e.g. a subnet-level block, or the implicit
            # default-deny at 32767). Same predicate as delete_oldest_acl_entry's fallback.
            deny_rules = [
                rule
                for rule in nacl["Entries"]
                if not rule["Egress"] and rule["RuleAction"] == "deny" and rule.get("CidrBlock", "").endswith("/32")
            ]

            # Check if we're approaching the limit (max 20 rules per direction)
            if len(deny_rules) >= 19:
                logger.warning(f"NACL {nacl['NetworkAclId']} has {len(deny_rules)} deny rules, performing aggressive cleanup.")
                # Rule numbers no longer indicate age once the allocator falls back to the high end,
                # so order by the DynamoDB created_at tracking data instead. Rules with no tracking
                # row have drifted from DynamoDB; treat them as oldest (safe to evict first) via the
                # "" sentinel, which sorts before any real timestamp string.
                created_at_by_rule_number: Dict[int, str] = {}
                try:
                    tracking = dynamodb_client.query(
                        TableName=GD_PATROL_TABLE,
                        KeyConditionExpression="#pk = :pk_value",
                        ExpressionAttributeNames={"#pk": "network_acl_id"},
                        ExpressionAttributeValues={":pk_value": {"S": nacl["NetworkAclId"]}},
                    )
                    for item in tracking.get("Items", []):
                        created_at_by_rule_number[int(item["rule_number"]["S"])] = item["created_at"]["S"]
                except Exception as e:
                    logger.error(f"Error querying DynamoDB for NACL {nacl['NetworkAclId']} during cleanup: {e}")
                # Newest first, so the 10 most recent are kept and the remainder (oldest) are deleted.
                deny_rules_sorted = sorted(
                    deny_rules, key=lambda r: created_at_by_rule_number.get(r["RuleNumber"], ""), reverse=True
                )
                # Keep only the 10 most recent rules
                rules_to_delete = deny_rules_sorted[10:]
                deleted_rule_numbers = set()
                for rule in rules_to_delete:
                    try:
                        ec2_client.delete_network_acl_entry(
                            Egress=False,
                            NetworkAclId=nacl["NetworkAclId"],
                            RuleNumber=rule["RuleNumber"],
                        )
                        deleted_rule_numbers.add(rule["RuleNumber"])
                        logger.info(f"Aggressively deleted deny rule {rule['RuleNumber']} in NACL {nacl['NetworkAclId']}")
                    except Exception as e:
                        logger.error(f"Failed to delete deny rule {rule['RuleNumber']}: {e}")
                delete_dynamodb_rule_entries(nacl["NetworkAclId"], deleted_rule_numbers)

            target_rule_number = _next_free_ingress_deny_rule_number(nacl["Entries"])
            if target_rule_number is None:
                logger.warning(f"No free ingress rule numbers in NACL {nacl['NetworkAclId']}; deleting oldest entry to make room")
                delete_oldest_acl_entry(nacl["NetworkAclId"])
                refreshed = ec2_client.describe_network_acls(NetworkAclIds=[nacl["NetworkAclId"]])["NetworkAcls"][0]
                target_rule_number = _next_free_ingress_deny_rule_number(refreshed["Entries"])
                if target_rule_number is None:
                    logger.error(f"NACL {nacl['NetworkAclId']} still has no free ingress rule numbers after cleanup; skipping")
                    continue

            try:
                _create_and_track_deny_rule(ip_address, nacl["NetworkAclId"], target_rule_number)
                logger.info(f"Blacklisted IP {ip_address} in NACL {nacl['NetworkAclId']}")
                blocked_count += 1

            except Exception as error:
                logger.info(f"INFO: {error}")
                if "NetworkAclEntryLimitExceeded" in str(error):
                    try:
                        logger.info(f"Network ACL limit exceeded for {nacl['NetworkAclId']}, attempting to delete oldest entry")
                        delete_oldest_acl_entry(nacl["NetworkAclId"])
                        # Retry creating the entry after deleting the oldest one
                        _create_and_track_deny_rule(ip_address, nacl["NetworkAclId"], target_rule_number)
                        logger.info(f"Blacklisted IP {ip_address} in NACL {nacl['NetworkAclId']} after deleting oldest entry")
                        blocked_count += 1
                    except Exception as retry_error:
                        logger.error(f"Failed to create entry after deleting oldest: {retry_error}")
                        # Try the next NACL
                        continue
                elif "NetworkAclEntryAlreadyExists" in str(error):
                    # Our snapshot of the NACL was stale (a concurrent mutation took this number);
                    # retry with a freshly-computed free number instead of failing outright.
                    logger.warning(f"Rule number {target_rule_number} already exists in {nacl['NetworkAclId']}; retrying with another")
                    retried_successfully = False
                    for _ in range(3):
                        refreshed = ec2_client.describe_network_acls(NetworkAclIds=[nacl["NetworkAclId"]])["NetworkAcls"][0]
                        retry_rule_number = _next_free_ingress_deny_rule_number(refreshed["Entries"])
                        if retry_rule_number is None:
                            break
                        try:
                            _create_and_track_deny_rule(ip_address, nacl["NetworkAclId"], retry_rule_number)
                            logger.info(f"Blacklisted IP {ip_address} in NACL {nacl['NetworkAclId']} at retried rule {retry_rule_number}")
                            blocked_count += 1
                            retried_successfully = True
                            break
                        except Exception as retry_error:
                            if "NetworkAclEntryAlreadyExists" not in str(retry_error):
                                logger.error(f"Failed to create entry at retried rule number: {retry_error}")
                                break
                    if not retried_successfully:
                        logger.error(f"Could not blacklist {ip_address} in NACL {nacl['NetworkAclId']}: no free rule number available")
                        continue
                else:
                    logger.error(f"Error creating network_acl entry: {error}")
                    continue

        if nacls and blocked_count == len(nacls):
            logger.info(f"Successfully blacklisted IP: {ip_address} in {blocked_count} NACL(s)")
            return True
        logger.error(f"Blacklisted IP {ip_address} in only {blocked_count}/{len(nacls)} NACLs")
        return False
    except Exception as e:
        logger.error(f"Error executing blacklist_ip: {e}")
        return False
    finally:
        if lock_acquired:
            release_lock(lock_table_name, lock_id)


def whitelist_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        logger.error(f"Invalid IP address: {ip_address}")
        return False

    lock_acquired = False
    try:
        acquire_lock(GD_PATROL_LOCK_TABLE, GD_PATROL_NACL_LOCK_ID)
        lock_acquired = True

        removed_count = 0
        paginator = ec2_client.get_paginator("describe_network_acls")
        for page in paginator.paginate():
            for nacl in page["NetworkAcls"]:
                removed_rule_numbers = set()
                for rule in nacl["Entries"]:
                    if rule.get("CidrBlock") == f"{ip_address}/32":
                        ec2_client.delete_network_acl_entry(
                            NetworkAclId=nacl["NetworkAclId"],
                            Egress=rule["Egress"],
                            RuleNumber=rule["RuleNumber"],
                        )
                        removed_count += 1
                        if not rule["Egress"]:
                            removed_rule_numbers.add(rule["RuleNumber"])
                delete_dynamodb_rule_entries(nacl["NetworkAclId"], removed_rule_numbers)

        if removed_count == 0:
            logger.warning(f"GDPatrol: No matching rules found to whitelist {ip_address}")
            return False
        logger.info(f"GDPatrol: Successfully executed action {stack()[0][3]} for {ip_address}")
        return True

    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False
    finally:
        if lock_acquired:
            release_lock(GD_PATROL_LOCK_TABLE, GD_PATROL_NACL_LOCK_ID)


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

        # NOTE: Assign the security group to every ENI — modify_instance_attribute only
        # touches the primary interface, leaving other ENIs unisolated.
        instance_described = client.describe_instances(InstanceIds=[instance_id])
        network_interfaces = instance_described["Reservations"][0]["Instances"][0]["NetworkInterfaces"]
        for eni in network_interfaces:
            client.modify_network_interface_attribute(NetworkInterfaceId=eni["NetworkInterfaceId"], Groups=[sg_id])

        logger.info(f"GDPatrol: Successfully executed action {stack()[0][3]} for {instance_id}")
        return True
    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False


def snapshot_instance(instance_id):
    try:
        client = boto3.client("ec2")
        instance_described = client.describe_instances(InstanceIds=[instance_id])
        blockmappings = instance_described["Reservations"][0]["Instances"][0]["BlockDeviceMappings"]
        for device in blockmappings:
            client.create_snapshot(
                VolumeId=device["Ebs"]["VolumeId"],
                Description=f"Created by GDpatrol for {instance_id}",
            )
        logger.info(f"GDPatrol: Successfully executed action {stack()[0][3]} for {instance_id}")
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
            PolicyDocument='{"Version":"2012-10-17", "Statement":{"Effect":"Deny", "Action":"*", "Resource":"*"}}',
        )
        logger.info(f"GDPatrol: Successfully executed action {stack()[0][3]} for {username}")
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
            PolicyDocument='{"Version":"2012-10-17", "Statement":{"Effect":"Deny", "Action":"ec2:*" , "Resource":"*"}}',
        )
        logger.info(f"GDPatrol: Successfully executed action {stack()[0][3]} for {username}")
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
        logger.info(f"GDPatrol: Successfully executed action {stack()[0][3]} for {username}")
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
        logger.info(f"GDPatrol: Successfully executed action {stack()[0][3]} for {username}")
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
        logger.info(f"GDPatrol: Successfully executed action {stack()[0][3]} for {username}")
        return True
    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False


def asg_detach_instance(instance_id):
    if not instance_id:
        logger.error(f"GDPatrol: {stack()[0][3]} called without an instance_id")
        return False
    try:
        client = boto3.client("autoscaling")
        response = client.describe_auto_scaling_instances(InstanceIds=[instance_id], MaxRecords=1)
        instances = response["AutoScalingInstances"]
        if not instances:
            logger.warning(f"GDPatrol: {instance_id} is not a member of any Auto Scaling Group; nothing to detach")
            return False

        asg_name = instances[0]["AutoScalingGroupName"]
        client.detach_instances(
            InstanceIds=[instance_id],
            AutoScalingGroupName=asg_name,
            ShouldDecrementDesiredCapacity=False,
        )
        logger.info(f"GDPatrol: Successfully executed action {stack()[0][3]} for {instance_id}")
        return True
    except Exception as e:
        logger.error(f"GDPatrol: Error executing {stack()[0][3]} - {e}")
        return False


def resolve_domain_a_records(domain: str, timeout: float = 5.0) -> List[str]:
    """
    Resolve all IPv4 (A record) addresses for a domain, bounded by a timeout so a
    slow or hostile nameserver can't hang the invocation. Resolution errors are
    swallowed, returning no addresses rather than raising.
    """
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        return sorted({result[4][0] for result in results})
    except OSError as e:
        logger.error(f"GDPatrol: Error resolving domain {domain} - {e}")
        return []
    finally:
        socket.setdefaulttimeout(previous_timeout)


class Config:
    def __init__(self, finding_type: str) -> None:
        self.finding_type = finding_type
        with open("config.json") as f:
            self.config = json.load(f)

    def get_actions(self) -> List[str]:
        for playbook in self.config["playbooks"]["playbook"]:
            if playbook["type"] == self.finding_type:
                return playbook["actions"] if isinstance(playbook["actions"], list) else [playbook["actions"]]
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
        logger.info(f"GDPatrol: Parsed Finding ID: {finding_id} - Finding Type: {finding_type}")
        config = Config(event["type"])
        severity = float(event.get("severity", 0) or 0)
        count = event.get("service", {}).get("count", 0)

        config_actions = config.get_actions()
        config_reliability = config.get_reliability()
        resource_type = event.get("resource", {}).get("resourceType")
    except (KeyError, ValueError, TypeError, FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"GDPatrol: Could not parse the Finding fields correctly, please verify that the JSON is correct. {e}")
        return
    instance_id = None
    vpc_id = None
    username = None
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
    elif action_type == "RDS_LOGIN_ATTEMPT":
        ip_address = event["service"]["action"]["rdsLoginAttemptAction"].get("remoteIpDetails", {}).get("ipAddressV4")

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
                domain_blocked = False
                for resolved_ip in resolve_domain_a_records(domain):
                    if blacklist_ip(resolved_ip):
                        domain_blocked = True
                successful_actions += int(domain_blocked)
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

    event_summary = summarize_event(event)
    event_service = event.get("service", {})
    event_severity = event.get("severity", 0)
    event_count = event_service.get("count", "N/A")

    # Build concise Slack fields from the summary
    fields = [
        {"title": "Region", "value": event_summary.get("region", "N/A"), "short": "true"},
        {"title": "Account", "value": event_summary.get("account", "N/A"), "short": "true"},
        {"title": "Finding Type", "value": event_summary.get("finding_type", "N/A"), "short": "true"},
        {"title": "Severity", "value": str(event_severity), "short": "true"},
        {"title": "First Seen", "value": event_service.get("eventFirstSeen", "N/A"), "short": "true"},
        {"title": "Last Seen", "value": event_service.get("eventLastSeen", "N/A"), "short": "true"},
        {"title": "Count", "value": str(event_count), "short": "true"},
        {"title": "Action Type", "value": event_summary.get("action_type", "N/A"), "short": "true"},
    ]

    # Add source info
    if "source_ip" in event_summary:
        fields.append({"title": "Source IP", "value": event_summary["source_ip"], "short": "true"})
    if "domain" in event_summary:
        fields.append({"title": "Domain", "value": event_summary["domain"], "short": "true"})
    if "api_call" in event_summary:
        fields.append({"title": "API Call", "value": event_summary["api_call"], "short": "true"})

    # Add target info
    if "instance_id" in event_summary:
        name = event_summary.get("instance_name", "")
        value = event_summary["instance_id"] + (f" ({name})" if name else "")
        fields.append({"title": "Instance", "value": value, "short": "true"})
    if "username" in event_summary:
        fields.append({"title": "User", "value": event_summary["username"], "short": "true"})
    if "db_instance" in event_summary:
        fields.append({"title": "DB Instance", "value": event_summary["db_instance"], "short": "true"})

    # Add description and actions summary
    fields.append({"title": "Description", "value": event_summary.get("description", "N/A")})
    fields.append(
        {
            "title": "Actions",
            "value": f"{successful_actions}/{actions_to_be_executed} executed ({total_config_actions} configured)",
            "short": "true",
        }
    )

    # Timestamp for the footer, computed per invocation
    st = datetime.datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S")
    guardduty_finding = {
        "attachments": [
            {
                "fallback": f"GuardDuty: {event_summary.get('finding_type', 'Unknown')}",
                "color": "#7e57c2",
                "title": f"GuardDuty Finding: {event_summary.get('finding_type', 'Unknown')}",
                "footer": f"GDPatrol | Finding {finding_id} | {st}",
                "fields": fields,
            }
        ]
    }
    if severity > 5:
        publish_message(slack_web_hook_url, json.dumps(guardduty_finding))
    logger.info(
        f"GDPatrol: Total actions: {total_config_actions} - Actions to be executed: {actions_to_be_executed} - Successful Actions: {successful_actions} - Finding ID:  {finding_id} - Finding Type: {finding_type}"
    )
