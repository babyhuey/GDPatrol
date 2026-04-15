import boto3
import time

ec2 = boto3.client("ec2")
dynamodb = boto3.client("dynamodb")
nacls = ec2.describe_network_acls()

for nacl in nacls["NetworkAcls"]:
    for rule in nacl["Entries"]:
        if rule["Egress"] is False and rule["RuleAction"] == "deny":
            dynamodb.put_item(
                TableName="GDPatrol",
                Item={
                    "network_acl_id": {
                        "S": nacl["NetworkAclId"],
                    },
                    "created_at": {
                        "S": str(time.time()),
                    },
                    "rule_number": {
                        "S": str(rule["RuleNumber"]),
                    },
                },
            )
            print(nacl["NetworkAclId"])
            print(time.time())
            print(rule["RuleNumber"])
            time.sleep(1)
