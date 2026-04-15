import pytest
import json
from unittest.mock import patch, MagicMock
import sys
import os
from pathlib import Path

# Add the parent directory to sys.path to import the lambda function
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from GDPatrol.lambda_function import (
    enhance_message_with_claude,
    publish_message,
    create_network_acl_entry,
    delete_oldest_acl_entry,
    acquire_lock,
    release_lock,
    blacklist_ip,
    whitelist_ip,
    quarantine_instance,
    snapshot_instance,
    disable_account,
    disable_ec2_access,
    enable_ec2_access,
    disable_sg_access,
    enable_sg_access,
    Config,
    lambda_handler,
)


def test_config_class():
    """Test the Config class functionality."""
    test_config_path = Path(__file__).parent / "test_config.json"

    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()

        config = Config("Backdoor:EC2/C&CActivity.B!DNS")

        actions = config.get_actions()
        assert isinstance(actions, list)
        assert "blacklist_domain" in actions
        assert "quarantine_instance" in actions

        reliability = config.get_reliability()
        assert isinstance(reliability, int)
        assert reliability == 5


def test_config_unknown_finding_type():
    """Test Config with an unknown finding type returns defaults."""
    test_config_path = Path(__file__).parent / "test_config.json"
    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()
        config = Config("InvalidFindingType")
        assert config.get_actions() == []
        assert config.get_reliability() == 5


@patch("GDPatrol.lambda_function.bedrock_client")
def test_enhance_message_with_claude(mock_bedrock):
    """Test that enhance_message_with_claude calls Bedrock and appends AI Analysis."""
    test_message = {"attachments": [{"fields": [{"title": "Test", "value": "Test Value"}]}]}

    mock_bedrock.invoke_model.return_value = {
        "body": MagicMock(read=lambda: json.dumps({"content": [{"text": "This is a security analysis."}]}).encode())
    }

    result = enhance_message_with_claude(test_message)

    mock_bedrock.invoke_model.assert_called_once()
    call_body = json.loads(mock_bedrock.invoke_model.call_args[1]["body"])
    assert call_body["anthropic_version"] == "bedrock-2023-05-31"
    assert len(call_body["messages"]) == 1
    assert call_body["messages"][0]["role"] == "user"

    field_titles = [f["title"] for f in result["attachments"][0]["fields"]]
    assert "AI Analysis" in field_titles
    ai_field = next(f for f in result["attachments"][0]["fields"] if f["title"] == "AI Analysis")
    assert ai_field["value"] == "This is a security analysis."


@patch("GDPatrol.lambda_function.bedrock_client")
def test_enhance_message_with_claude_error_returns_original(mock_bedrock):
    """Test that Bedrock errors don't break the message — returns original."""
    test_message = {"attachments": [{"fields": [{"title": "Test", "value": "Test Value"}]}]}
    mock_bedrock.invoke_model.side_effect = Exception("Bedrock unavailable")

    result = enhance_message_with_claude(test_message)

    assert result == test_message
    assert len(result["attachments"][0]["fields"]) == 1


@patch("GDPatrol.lambda_function.enhance_message_with_claude")
@patch("requests.post")
def test_publish_message(mock_post, mock_enhance):
    """Test Slack message publishing calls enhance then posts."""
    mock_enhance.return_value = {"attachments": [{"fields": []}]}

    publish_message(
        "https://hooks.slack.com/services/test",
        json.dumps({"attachments": [{"fields": []}]}),
    )

    mock_enhance.assert_called_once()
    mock_post.assert_called_once()


def test_create_network_acl_entry(mock_ec2_client):
    """Test network ACL entry creation."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    nacl = mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])

    create_network_acl_entry("10.0.0.1", nacl["NetworkAcl"]["NetworkAclId"], 100)

    nacl_entries = mock_ec2_client.describe_network_acls(NetworkAclIds=[nacl["NetworkAcl"]["NetworkAclId"]])["NetworkAcls"][0]["Entries"]

    assert any(
        entry["RuleNumber"] == 100 and entry["CidrBlock"] == "10.0.0.1/32" and entry["RuleAction"] == "deny" for entry in nacl_entries
    )


def create_lock_table(dynamodb_client):
    dynamodb_client.create_table(
        TableName="GDPatrol_lock",
        KeySchema=[{"AttributeName": "lock_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "lock_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def create_gdpatrol_table(dynamodb_client):
    dynamodb_client.create_table(
        TableName="GDPatrol",
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


def test_blacklist_ip(mock_ec2_client, mock_dynamodb_client):
    """Test IP blacklisting functionality."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    create_gdpatrol_table(mock_dynamodb_client)
    create_lock_table(mock_dynamodb_client)

    result = blacklist_ip("10.0.0.1")
    assert result is True


@patch("boto3.client")
def test_lambda_handler_ec2_finding(
    mock_boto3_client,
    sample_guardduty_event,
    mock_ec2_client,
    mock_dynamodb_client,
    mock_bedrock_response,
    monkeypatch,
):
    """Test the lambda handler with an EC2 finding."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test/webhook")

    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    create_gdpatrol_table(mock_dynamodb_client)
    create_lock_table(mock_dynamodb_client)

    mock_bedrock = MagicMock()
    mock_boto3_client.return_value = mock_bedrock
    mock_bedrock.invoke_model.return_value = mock_bedrock_response

    test_config_path = Path(__file__).parent / "test_config.json"
    with patch("builtins.open", MagicMock()) as mock_open, patch("GDPatrol.lambda_function.publish_message") as mock_publish:
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()
        lambda_handler(sample_guardduty_event, None)
        mock_publish.assert_called()


def test_lambda_handler_rds_finding(
    sample_rds_guardduty_event,
    monkeypatch,
):
    """Test the lambda handler correctly extracts IP from RDS_LOGIN_ATTEMPT events."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    test_config_path = Path(__file__).parent / "test_config.json"
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message"),
        patch("GDPatrol.lambda_function.blacklist_ip") as mock_blacklist,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()
        # RDS finding with severity 5 + reliability 5 = 10, won't execute
        lambda_handler(sample_rds_guardduty_event, None)
        mock_blacklist.assert_not_called()

        # Bump severity so it triggers (severity 8 + reliability 5 = 13 > 10)
        sample_rds_guardduty_event["severity"] = 8
        lambda_handler(sample_rds_guardduty_event, None)
        mock_blacklist.assert_called_once_with("203.0.113.50")


def test_lambda_handler_missing_fields():
    """Test lambda handler handles missing required fields gracefully."""
    bad_event = {"foo": "bar"}
    # Should not raise
    lambda_handler(bad_event, None)


@patch("boto3.client")
@pytest.mark.parametrize(
    "ip_address,expected",
    [
        ("10.0.0.1", True),
        ("192.168.1.1", True),
        ("invalid-ip", False),
    ],
)
def test_blacklist_ip_parameterized(mock_boto3_client, ip_address, expected, mock_ec2_client, mock_dynamodb_client):
    """Parameterized test for blacklist_ip function."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    create_gdpatrol_table(mock_dynamodb_client)
    create_lock_table(mock_dynamodb_client)

    if expected:
        assert blacklist_ip(ip_address) is True
    else:
        assert blacklist_ip(ip_address) is False


# --- delete_oldest_acl_entry tests ---


@patch("GDPatrol.lambda_function.dynamodb_client")
@patch("GDPatrol.lambda_function.ec2_client")
def test_delete_oldest_acl_entry_from_dynamodb(mock_ec2, mock_dynamo):
    """Test deleting oldest ACL entry when DynamoDB has entries."""
    mock_dynamo.query.return_value = {
        "Items": [
            {
                "network_acl_id": {"S": "acl-123"},
                "created_at": {"S": "1000.0"},
                "rule_number": {"S": "50"},
            }
        ]
    }

    delete_oldest_acl_entry("acl-123")

    mock_ec2.delete_network_acl_entry.assert_called_once()
    mock_dynamo.delete_item.assert_called_once()


@patch("GDPatrol.lambda_function.dynamodb_client")
@patch("GDPatrol.lambda_function.ec2_client")
def test_delete_oldest_acl_entry_fallback_to_aws(mock_ec2, mock_dynamo):
    """Test fallback to AWS NACL entries when DynamoDB is empty."""
    mock_dynamo.query.return_value = {"Items": []}
    mock_ec2.describe_network_acls.return_value = {
        "NetworkAcls": [
            {
                "Entries": [
                    {"Egress": False, "RuleAction": "deny", "RuleNumber": 10, "CidrBlock": "1.2.3.4/32"},
                    {"Egress": False, "RuleAction": "deny", "RuleNumber": 20, "CidrBlock": "5.6.7.8/32"},
                    {"Egress": False, "RuleAction": "allow", "RuleNumber": 100, "CidrBlock": "0.0.0.0/0"},
                ]
            }
        ]
    }

    delete_oldest_acl_entry("acl-123")

    mock_ec2.delete_network_acl_entry.assert_called_once()
    call_kwargs = mock_ec2.delete_network_acl_entry.call_args[1]
    assert call_kwargs["RuleNumber"] == 10  # lowest deny rule


@patch("GDPatrol.lambda_function.dynamodb_client")
@patch("GDPatrol.lambda_function.ec2_client")
def test_delete_oldest_acl_entry_no_deny_rules(mock_ec2, mock_dynamo):
    """Test fallback when no deny rules exist — should do nothing."""
    mock_dynamo.query.return_value = {"Items": []}
    mock_ec2.describe_network_acls.return_value = {
        "NetworkAcls": [
            {
                "Entries": [
                    {"Egress": False, "RuleAction": "allow", "RuleNumber": 100, "CidrBlock": "0.0.0.0/0"},
                ]
            }
        ]
    }

    delete_oldest_acl_entry("acl-123")

    mock_ec2.delete_network_acl_entry.assert_not_called()


# --- Lock tests ---


@patch("GDPatrol.lambda_function.dynamodb_client")
def test_acquire_and_release_lock(mock_dynamo):
    """Test acquiring and releasing a lock."""
    mock_dynamo.get_item.return_value = {}  # no existing lock
    mock_dynamo.exceptions = MagicMock()
    mock_dynamo.exceptions.ConditionalCheckFailedException = type("ConditionalCheckFailedException", (Exception,), {})

    acquire_lock("GDPatrol_lock", "test-lock")
    mock_dynamo.put_item.assert_called_once()

    release_lock("GDPatrol_lock", "test-lock")
    mock_dynamo.delete_item.assert_called_once()


# --- whitelist_ip tests ---


def test_whitelist_ip(mock_ec2_client):
    """Test whitelisting (removing) an IP from NACLs."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    nacl = mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    nacl_id = nacl["NetworkAcl"]["NetworkAclId"]

    # Add a deny rule first
    mock_ec2_client.create_network_acl_entry(
        CidrBlock="192.168.1.1/32",
        Egress=False,
        NetworkAclId=nacl_id,
        Protocol="-1",
        RuleAction="deny",
        RuleNumber=100,
    )

    result = whitelist_ip("192.168.1.1")
    assert result is True

    # Verify the rule was removed
    entries = mock_ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]["Entries"]
    assert not any(e.get("CidrBlock") == "192.168.1.1/32" and e["RuleAction"] == "deny" for e in entries)


# --- IAM action tests ---


def test_disable_account(mock_ec2_client, aws_credentials):
    """Test disabling an IAM account."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="testuser")
        result = disable_account("testuser")
        assert result is True

        policies = iam.list_user_policies(UserName="testuser")
        assert "BlockAllPolicy" in policies["PolicyNames"]


def test_disable_ec2_access(aws_credentials):
    """Test disabling EC2 access for a user."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="testuser")
        result = disable_ec2_access("testuser")
        assert result is True

        policies = iam.list_user_policies(UserName="testuser")
        assert "BlockEC2Policy" in policies["PolicyNames"]


def test_enable_ec2_access(aws_credentials):
    """Test re-enabling EC2 access by removing the block policy."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="testuser")
        # First disable
        disable_ec2_access("testuser")
        # Then enable
        result = enable_ec2_access("testuser")
        assert result is True

        policies = iam.list_user_policies(UserName="testuser")
        assert "BlockEC2Policy" not in policies["PolicyNames"]


def test_disable_sg_access(aws_credentials):
    """Test disabling security group access."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="testuser")
        result = disable_sg_access("testuser")
        assert result is True

        policies = iam.list_user_policies(UserName="testuser")
        assert "BlockSecurityGroupPolicy" in policies["PolicyNames"]


def test_enable_sg_access(aws_credentials):
    """Test re-enabling security group access."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="testuser")
        disable_sg_access("testuser")
        result = enable_sg_access("testuser")
        assert result is True

        policies = iam.list_user_policies(UserName="testuser")
        assert "BlockSecurityGroupPolicy" not in policies["PolicyNames"]


# --- EC2 action tests ---


def test_quarantine_instance(mock_ec2_client):
    """Test quarantining an EC2 instance."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    subnet = mock_ec2_client.create_subnet(VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.1.0/24")
    instance = mock_ec2_client.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet["Subnet"]["SubnetId"],
    )
    instance_id = instance["Instances"][0]["InstanceId"]

    result = quarantine_instance(instance_id, vpc["Vpc"]["VpcId"])
    assert result is True

    # Verify instance has a quarantine security group
    instance_desc = mock_ec2_client.describe_instances(InstanceIds=[instance_id])
    sgs = instance_desc["Reservations"][0]["Instances"][0]["SecurityGroups"]
    assert any("Quarantine" in sg["GroupName"] for sg in sgs)


def test_snapshot_instance(mock_ec2_client):
    """Test snapshotting an EC2 instance's volumes."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    subnet = mock_ec2_client.create_subnet(VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.1.0/24")
    instance = mock_ec2_client.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet["Subnet"]["SubnetId"],
    )
    instance_id = instance["Instances"][0]["InstanceId"]

    result = snapshot_instance(instance_id)
    assert result is True


# --- lambda_handler action dispatch tests ---


def test_lambda_handler_blacklist_ip_count_threshold(monkeypatch):
    """Test that blacklist_ip triggers on count > 100 even when severity + reliability <= 10."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-id",
        "type": "Recon:EC2/PortProbeUnprotectedPort",
        "severity": 2,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": "i-abc",
                "networkInterfaces": [{"vpcId": "vpc-abc"}],
            },
        },
        "service": {
            "action": {
                "actionType": "PORT_PROBE",
                "portProbeAction": {"portProbeDetails": [{"remoteIpDetails": {"ipAddressV4": "1.2.3.4"}}]},
            },
            "count": 200,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "Port probe",
    }

    test_config_path = Path(__file__).parent / "test_config.json"
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message"),
        patch("GDPatrol.lambda_function.blacklist_ip") as mock_blacklist,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()
        mock_blacklist.return_value = True
        lambda_handler(event, None)
        # severity 2 + reliability 5 = 7, not > 10, but count 200 > 100
        mock_blacklist.assert_called_once_with("1.2.3.4")


def test_lambda_handler_iam_finding(monkeypatch):
    """Test lambda handler with an IAM AccessKey finding dispatches disable_account."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-iam-id",
        "type": "Recon:IAMUser/MaliciousIPCaller",
        "severity": 8,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {"userName": "baduser"},
        },
        "service": {
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {
                    "remoteIpDetails": {"ipAddressV4": "9.8.7.6"},
                },
            },
            "count": 1,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "IAM recon",
    }

    test_config_path = Path(__file__).parent / "test_config.json"
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message"),
        patch("GDPatrol.lambda_function.disable_account") as mock_disable,
    ):
        # Add the IAM finding type to the mock config
        config_data = json.loads(test_config_path.read_text())
        config_data["playbooks"]["playbook"].append(
            {
                "type": "Recon:IAMUser/MaliciousIPCaller",
                "actions": ["disable_account"],
                "reliability": 5,
            }
        )
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(config_data)
        mock_disable.return_value = True
        lambda_handler(event, None)
        mock_disable.assert_called_once_with("baduser")
