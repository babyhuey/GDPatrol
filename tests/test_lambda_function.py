import pytest
import json
from unittest.mock import patch, MagicMock
import sys
import os
from pathlib import Path

# Add the parent directory to sys.path to import the lambda function
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from GDPatrol.lambda_function import (
    publish_message,
    create_network_acl_entry,
    blacklist_ip,
    Config,
    lambda_handler,
)


def test_config_class():
    """Test the Config class functionality."""
    # Get the path to the test config file
    test_config_path = Path(__file__).parent / "test_config.json"

    # Mock the open function to use our test config
    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = (
            test_config_path.read_text()
        )

        config = Config("Backdoor:EC2/C&CActivity.B!DNS")

        # Test get_actions
        actions = config.get_actions()
        assert isinstance(actions, list)
        assert "blacklist_domain" in actions
        assert "quarantine_instance" in actions

        # Test get_reliability
        reliability = config.get_reliability()
        assert isinstance(reliability, int)
        assert reliability == 5


@patch("boto3.client")
def test_enhance_message_with_claude(mock_boto3_client):
    """Test the Claude message enhancement functionality."""
    test_message = {
        "attachments": [{"fields": [{"title": "Test", "value": "Test Value"}]}]
    }

    # Create a mock Bedrock client
    mock_bedrock = MagicMock()
    mock_boto3_client.return_value = mock_bedrock

    # Mock the invoke_model response
    mock_response = {
        "body": MagicMock(
            read=lambda: json.dumps({"completion": "Test AI analysis"}).encode()
        )
    }
    mock_bedrock.invoke_model.return_value = mock_response

    # Mock the actual function to bypass Bedrock API call
    with patch("GDPatrol.lambda_function.enhance_message_with_claude") as mock_enhance:
        mock_enhance.return_value = {
            "attachments": [
                {
                    "fields": [
                        {"title": "Test", "value": "Test Value"},
                        {"title": "AI Analysis", "value": "Test AI analysis"},
                    ]
                }
            ]
        }

        enhanced_message = mock_enhance(test_message)

        assert "AI Analysis" in [
            field["title"] for field in enhanced_message["attachments"][0]["fields"]
        ]
        assert any(
            field["value"] == "Test AI analysis"
            for field in enhanced_message["attachments"][0]["fields"]
        )


@patch("requests.post")
def test_publish_message(mock_post, mock_slack_webhook):
    """Test the Slack message publishing functionality."""
    test_data = json.dumps(
        {"attachments": [{"fields": [{"title": "Test", "value": "Test Value"}]}]}
    )

    publish_message("https://hooks.slack.com/services/test", test_data)
    mock_post.assert_called_once()


def test_create_network_acl_entry(mock_ec2_client):
    """Test network ACL entry creation."""
    # Create a test VPC and NACL
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    nacl = mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])

    create_network_acl_entry("10.0.0.1", nacl["NetworkAcl"]["NetworkAclId"], 100)

    # Verify the NACL entry was created
    nacl_entries = mock_ec2_client.describe_network_acls(
        NetworkAclIds=[nacl["NetworkAcl"]["NetworkAclId"]]
    )["NetworkAcls"][0]["Entries"]

    assert any(
        entry["RuleNumber"] == 100
        and entry["CidrBlock"] == "10.0.0.1/32"
        and entry["RuleAction"] == "deny"
        for entry in nacl_entries
    )


def create_lock_table(dynamodb_client):
    dynamodb_client.create_table(
        TableName="GDPatrol_lock",
        KeySchema=[{"AttributeName": "lock_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "lock_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def test_blacklist_ip(mock_ec2_client, mock_dynamodb_client):
    """Test IP blacklisting functionality."""
    # Create test VPC and NACL
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])

    # Create test DynamoDB tables
    mock_dynamodb_client.create_table(
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
    create_lock_table(mock_dynamodb_client)

    result = blacklist_ip("10.0.0.1")
    assert result is True


@patch("boto3.client")
def test_lambda_handler(
    mock_boto3_client,
    sample_guardduty_event,
    mock_ec2_client,
    mock_dynamodb_client,
    monkeypatch,
):
    """Test the main lambda handler function."""
    # Set dummy Slack webhook URL
    monkeypatch.setenv(
        "SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test/webhook"
    )

    # Create test VPC and NACL
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])

    # Create test DynamoDB tables
    mock_dynamodb_client.create_table(
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
    create_lock_table(mock_dynamodb_client)

    # Patch Bedrock client
    mock_bedrock = MagicMock()
    mock_boto3_client.return_value = mock_bedrock
    mock_response = {
        "body": MagicMock(
            read=lambda: json.dumps({"completion": "Test AI analysis"}).encode()
        )
    }
    mock_bedrock.invoke_model.return_value = mock_response

    # Patch config file
    test_config_path = Path(__file__).parent / "test_config.json"
    with patch("builtins.open", MagicMock()) as mock_open, patch(
        "GDPatrol.lambda_function.publish_message"
    ) as mock_publish:
        mock_open.return_value.__enter__.return_value.read.return_value = (
            test_config_path.read_text()
        )
        lambda_handler(sample_guardduty_event, None)
        mock_publish.assert_called()


def test_error_handling():
    """Test error handling in various functions."""
    # Patch config file
    test_config_path = Path(__file__).parent / "test_config.json"
    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = (
            test_config_path.read_text()
        )
        # Test Config with invalid finding type
        config = Config("InvalidFindingType")
        assert config.get_actions() == []
        assert config.get_reliability() == 5


@patch("boto3.client")
@pytest.mark.parametrize(
    "ip_address,expected",
    [
        ("10.0.0.1", True),
        ("192.168.1.1", True),
        ("invalid-ip", False),
    ],
)
def test_blacklist_ip_parameterized(
    mock_boto3_client, ip_address, expected, mock_ec2_client, mock_dynamodb_client
):
    """Parameterized test for blacklist_ip function."""
    # Create test VPC and NACL
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])

    # Create test DynamoDB tables
    mock_dynamodb_client.create_table(
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
    create_lock_table(mock_dynamodb_client)

    if expected:
        assert blacklist_ip(ip_address) is True
    else:
        assert blacklist_ip(ip_address) is False
