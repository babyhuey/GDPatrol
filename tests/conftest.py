import pytest
import boto3
from moto import mock_aws
import json
import os


@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def sample_guardduty_event():
    """Sample GuardDuty event for testing."""
    return {
        "id": "test-finding-id",
        "type": "Backdoor:EC2/C&CActivity.B!DNS",
        "severity": 7,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": "i-1234567890abcdef0",
                "networkInterfaces": [{"vpcId": "vpc-12345678"}],
            },
        },
        "service": {
            "action": {
                "actionType": "DNS_REQUEST",
                "dnsRequestAction": {"domain": "malicious.example.com"},
            },
            "count": 1,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "Test finding description",
    }


@pytest.fixture
def mock_ec2_client(aws_credentials):
    """Mocked EC2 client."""
    with mock_aws():
        yield boto3.client("ec2")


@pytest.fixture
def mock_dynamodb_client(aws_credentials):
    """Mocked DynamoDB client."""
    with mock_aws():
        yield boto3.client("dynamodb")


@pytest.fixture
def mock_bedrock_client(aws_credentials):
    """Mocked Bedrock client."""
    with mock_aws():
        yield boto3.client("bedrock-runtime")


@pytest.fixture
def mock_slack_webhook(monkeypatch):
    """Mock Slack webhook URL."""
    monkeypatch.setenv("slack_web_hook_url", "https://hooks.slack.com/services/test")
