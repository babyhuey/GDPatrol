import boto3
import time

TABLE_NAME = "GDPatrol"


def _already_tracked(dynamodb, network_acl_id: str, rule_number: str) -> bool:
    """Check whether a tracking row already exists for this NACL rule, so re-running this script is idempotent."""
    response = dynamodb.query(
        TableName=TABLE_NAME,
        KeyConditionExpression="#pk = :pk_value",
        FilterExpression="#rn = :rule_number",
        ExpressionAttributeNames={"#pk": "network_acl_id", "#rn": "rule_number"},
        ExpressionAttributeValues={
            ":pk_value": {"S": network_acl_id},
            ":rule_number": {"S": rule_number},
        },
    )
    return bool(response.get("Items"))


def seed_tracking_table():
    ec2 = boto3.client("ec2")
    dynamodb = boto3.client("dynamodb")
    nacls = ec2.describe_network_acls()

    for nacl in nacls["NetworkAcls"]:
        for rule in nacl["Entries"]:
            # Only track rules GDPatrol itself manages: ingress deny rules with a /32
            # CidrBlock. This excludes AWS's implicit undeletable default-deny
            # (0.0.0.0/0 @ rule 32767) and customer subnet-level denies, which would
            # otherwise poison delete_oldest_acl_entry.
            if rule["Egress"] or rule["RuleAction"] != "deny" or not rule.get("CidrBlock", "").endswith("/32"):
                continue

            network_acl_id = nacl["NetworkAclId"]
            rule_number = str(rule["RuleNumber"])
            if _already_tracked(dynamodb, network_acl_id, rule_number):
                continue

            dynamodb.put_item(
                TableName=TABLE_NAME,
                Item={
                    "network_acl_id": {
                        "S": network_acl_id,
                    },
                    "created_at": {
                        "S": str(time.time()),
                    },
                    "rule_number": {
                        "S": rule_number,
                    },
                },
            )
            print(f"Tracked {network_acl_id} rule {rule_number}")


if __name__ == "__main__":
    seed_tracking_table()
