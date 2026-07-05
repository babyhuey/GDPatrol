import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nacl_import import TABLE_NAME, seed_tracking_table


def create_gdpatrol_table(dynamodb_client):
    dynamodb_client.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {"AttributeName": "network_acl_id", "KeyType": "HASH"},
            {"AttributeName": "created_at", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "network_acl_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def test_seed_tracking_table_excludes_default_deny(mock_ec2_client, mock_dynamodb_client):
    """Only ingress deny rules with a /32 CidrBlock (GDPatrol-managed) get seeded;
    the implicit undeletable default-deny at rule 32767 must be excluded."""
    create_gdpatrol_table(mock_dynamodb_client)
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    nacl_id = mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])["NetworkAcl"]["NetworkAclId"]

    mock_ec2_client.create_network_acl_entry(
        NetworkAclId=nacl_id, RuleNumber=32767, Protocol="-1", RuleAction="deny", Egress=False, CidrBlock="0.0.0.0/0"
    )
    mock_ec2_client.create_network_acl_entry(
        NetworkAclId=nacl_id, RuleNumber=100, Protocol="-1", RuleAction="deny", Egress=False, CidrBlock="198.51.100.5/32"
    )

    seed_tracking_table()

    items = mock_dynamodb_client.scan(TableName=TABLE_NAME)["Items"]
    assert len(items) == 1
    assert items[0]["network_acl_id"]["S"] == nacl_id
    assert items[0]["rule_number"]["S"] == "100"


def test_seed_tracking_table_is_idempotent(mock_ec2_client, mock_dynamodb_client):
    """Re-running the seeder must not duplicate a tracking row for the same rule."""
    create_gdpatrol_table(mock_dynamodb_client)
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    nacl_id = mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])["NetworkAcl"]["NetworkAclId"]
    mock_ec2_client.create_network_acl_entry(
        NetworkAclId=nacl_id, RuleNumber=100, Protocol="-1", RuleAction="deny", Egress=False, CidrBlock="198.51.100.5/32"
    )

    seed_tracking_table()
    seed_tracking_table()

    items = mock_dynamodb_client.scan(TableName=TABLE_NAME)["Items"]
    assert len(items) == 1
