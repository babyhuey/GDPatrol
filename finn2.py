import boto3

client = boto3.client("ec2")
dynamodb_client = boto3.client('dynamodb')
nacls = client.describe_network_acls()
for nacl in nacls["NetworkAcls"]:
    print(nacl["NetworkAclId"])
    # print(nacl)
    min_rule_id = min(
        rule["RuleNumber"] for rule in nacl["Entries"] if not rule["Egress"] and rule["RuleAction"] == "deny"
    )
    print(min_rule_id)