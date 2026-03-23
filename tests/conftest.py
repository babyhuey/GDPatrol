import pytest
import boto3
from moto import mock_aws
from unittest.mock import MagicMock
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
def sample_rds_guardduty_event():
    """Sample RDS GuardDuty event for testing."""
    return {
        "id": "test-rds-finding-id",
        "type": "Discovery:RDS/MaliciousIPCaller",
        "severity": 5,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {
            "resourceType": "RDSDBInstance",
            "rdsDbInstanceDetails": {
                "dbInstanceIdentifier": "testdb",
                "dbClusterIdentifier": "test-cluster",
                "engine": "Aurora MySQL",
            },
        },
        "service": {
            "action": {
                "actionType": "RDS_LOGIN_ATTEMPT",
                "rdsLoginAttemptAction": {
                    "remoteIpDetails": {
                        "ipAddressV4": "203.0.113.50",
                        "organization": {
                            "asn": "12345",
                            "asnOrg": "Test Org",
                            "isp": "Test ISP",
                            "org": "Test Org",
                        },
                    }
                },
            },
            "count": 1,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "Test RDS finding description",
    }


@pytest.fixture
def sample_ssh_bruteforce_event():
    """Sample SSH brute force event with high severity + reliability."""
    return {
        "id": "test-ssh-finding-id",
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "severity": 8,
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
                "actionType": "NETWORK_CONNECTION",
                "networkConnectionAction": {
                    "remoteIpDetails": {"ipAddressV4": "198.51.100.99"},
                },
            },
            "count": 500,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "SSH brute force attempt",
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
def mock_bedrock_response():
    """Mock Bedrock response in Messages API format."""
    return {
        "body": MagicMock(
            read=lambda: b'{"content": [{"text": "Test AI analysis: This alert indicates suspicious activity."}]}'
        )
    }


@pytest.fixture
def mock_slack_webhook(monkeypatch):
    """Mock Slack webhook URL."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")
