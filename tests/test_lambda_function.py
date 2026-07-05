import pytest
import json
import time
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
    delete_dynamodb_rule_entries,
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
    asg_detach_instance,
    _next_free_ingress_deny_rule_number,
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
    assert mock_bedrock.invoke_model.call_args[1]["modelId"] == "global.anthropic.claude-sonnet-4-6"
    call_body = json.loads(mock_bedrock.invoke_model.call_args[1]["body"])
    assert call_body["anthropic_version"] == "bedrock-2023-05-31"
    assert "top_p" not in call_body  # temperature and top_p are mutually exclusive on Claude 4.x
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


def test_blacklist_ip_blocks_all_nacls(mock_ec2_client, mock_dynamodb_client):
    """blacklist_ip must add a deny rule to every NACL, not just the first one."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    create_gdpatrol_table(mock_dynamodb_client)
    create_lock_table(mock_dynamodb_client)

    assert blacklist_ip("203.0.113.9") is True

    for nacl in mock_ec2_client.describe_network_acls()["NetworkAcls"]:
        assert any(not e["Egress"] and e["RuleAction"] == "deny" and e.get("CidrBlock") == "203.0.113.9/32" for e in nacl["Entries"]), (
            f"IP not blocked in NACL {nacl['NetworkAclId']}"
        )


@patch("GDPatrol.lambda_function.release_lock")
@patch("GDPatrol.lambda_function.acquire_lock")
def test_blacklist_ip_no_release_when_acquire_fails(mock_acquire, mock_release):
    """A failed acquire_lock must not release another invocation's lock."""
    mock_acquire.side_effect = Exception("Unable to acquire lock after multiple attempts")
    assert blacklist_ip("198.51.100.1") is False
    mock_release.assert_not_called()


@patch("GDPatrol.lambda_function.release_lock")
def test_blacklist_ip_invalid_ip_does_not_touch_lock(mock_release):
    """An invalid IP returns False before any locking happens."""
    assert blacklist_ip("not-an-ip") is False
    mock_release.assert_not_called()


def test_whitelist_ip_cleans_dynamodb(mock_ec2_client, mock_dynamodb_client):
    """Whitelisting an IP also removes the DynamoDB entries for the deleted rules."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    create_gdpatrol_table(mock_dynamodb_client)
    create_lock_table(mock_dynamodb_client)

    assert blacklist_ip("203.0.113.77") is True
    assert mock_dynamodb_client.scan(TableName="GDPatrol")["Count"] > 0

    assert whitelist_ip("203.0.113.77") is True
    assert mock_dynamodb_client.scan(TableName="GDPatrol")["Count"] == 0


def test_delete_dynamodb_rule_entries(mock_dynamodb_client):
    """Only the entries matching the deleted rule numbers are removed."""
    create_gdpatrol_table(mock_dynamodb_client)
    for created_at, rule_number in [("100.0", "50"), ("200.0", "60")]:
        mock_dynamodb_client.put_item(
            TableName="GDPatrol",
            Item={
                "network_acl_id": {"S": "acl-123"},
                "created_at": {"S": created_at},
                "rule_number": {"S": rule_number},
            },
        )

    delete_dynamodb_rule_entries("acl-123", {50})

    items = mock_dynamodb_client.scan(TableName="GDPatrol")["Items"]
    assert len(items) == 1
    assert items[0]["rule_number"]["S"] == "60"


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


def test_blacklist_ip_skips_colliding_allow_rule(mock_ec2_client, mock_dynamodb_client):
    """The preferred rule number must never collide with, or evict, a pre-existing ALLOW rule."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    nacl = mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    nacl_id = nacl["NetworkAcl"]["NetworkAclId"]
    create_gdpatrol_table(mock_dynamodb_client)
    create_lock_table(mock_dynamodb_client)

    # An existing GDPatrol deny rule at 100, and a customer ALLOW rule sitting exactly
    # at the preferred next slot (99).
    mock_ec2_client.create_network_acl_entry(
        CidrBlock="9.9.9.9/32", Egress=False, NetworkAclId=nacl_id, Protocol="-1", RuleAction="deny", RuleNumber=100
    )
    mock_ec2_client.create_network_acl_entry(
        CidrBlock="10.0.0.0/24", Egress=False, NetworkAclId=nacl_id, Protocol="-1", RuleAction="allow", RuleNumber=99
    )

    assert blacklist_ip("203.0.113.5") is True

    entries = mock_ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]["Entries"]
    new_rule = next(e for e in entries if e.get("CidrBlock") == "203.0.113.5/32")
    assert new_rule["RuleNumber"] == 98
    assert any(e["RuleNumber"] == 99 and e["RuleAction"] == "allow" for e in entries), "pre-existing allow rule was evicted"


def test_blacklist_ip_low_end_exhaustion_does_not_evict(mock_ec2_client, mock_dynamodb_client):
    """When the low end is exhausted, blacklist_ip must search the high end instead of evicting
    whoever holds the old hardcoded wraparound slot (32700)."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    nacl = mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    nacl_id = nacl["NetworkAcl"]["NetworkAclId"]
    create_gdpatrol_table(mock_dynamodb_client)
    create_lock_table(mock_dynamodb_client)

    # A GDPatrol deny rule already sits at the lowest usable number.
    mock_ec2_client.create_network_acl_entry(
        CidrBlock="9.9.9.9/32", Egress=False, NetworkAclId=nacl_id, Protocol="-1", RuleAction="deny", RuleNumber=1
    )
    # Something else already occupies the old hardcoded wraparound target.
    mock_ec2_client.create_network_acl_entry(
        CidrBlock="10.0.5.0/24", Egress=False, NetworkAclId=nacl_id, Protocol="-1", RuleAction="deny", RuleNumber=32700
    )

    assert blacklist_ip("203.0.113.6") is True

    entries = mock_ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]["Entries"]
    assert any(e["RuleNumber"] == 32700 and e.get("CidrBlock") == "10.0.5.0/24" for e in entries), (
        "pre-existing occupant of rule 32700 was evicted"
    )
    new_rule = next(e for e in entries if e.get("CidrBlock") == "203.0.113.6/32")
    assert new_rule["RuleNumber"] == 32766


@patch("GDPatrol.lambda_function.dynamodb_client")
@patch("GDPatrol.lambda_function.delete_oldest_acl_entry")
@patch("GDPatrol.lambda_function.create_network_acl_entry")
@patch("GDPatrol.lambda_function._next_free_ingress_deny_rule_number")
@patch("GDPatrol.lambda_function.ec2_client")
def test_blacklist_ip_cleans_up_when_no_free_rule_number(mock_ec2, mock_next_free, mock_create_entry, mock_delete_oldest, mock_dynamo):
    """When the helper reports no free rule number, blacklist_ip must delete the oldest entry and retry."""
    nacl = {"NetworkAclId": "acl-1", "Entries": [{"Egress": False, "RuleAction": "deny", "RuleNumber": 5, "CidrBlock": "9.9.9.9/32"}]}
    mock_ec2.get_paginator.return_value.paginate.return_value = [{"NetworkAcls": [nacl]}]
    mock_ec2.describe_network_acls.return_value = {"NetworkAcls": [nacl]}
    mock_next_free.side_effect = [None, 42]
    mock_dynamo.exceptions = MagicMock()

    with patch("GDPatrol.lambda_function.acquire_lock"), patch("GDPatrol.lambda_function.release_lock"):
        result = blacklist_ip("10.0.0.1")

    mock_delete_oldest.assert_called_once_with("acl-1")
    mock_create_entry.assert_called_once_with("10.0.0.1", "acl-1", 42)
    assert result is True


@patch("GDPatrol.lambda_function.dynamodb_client")
@patch("GDPatrol.lambda_function.create_network_acl_entry")
@patch("GDPatrol.lambda_function._next_free_ingress_deny_rule_number")
@patch("GDPatrol.lambda_function.ec2_client")
def test_blacklist_ip_retries_on_already_exists(mock_ec2, mock_next_free, mock_create_entry, mock_dynamo):
    """A NetworkAclEntryAlreadyExists error on create must retry with a fresh free number, not fail
    the whole NACL silently."""
    from botocore.exceptions import ClientError

    nacl = {"NetworkAclId": "acl-1", "Entries": []}
    mock_ec2.get_paginator.return_value.paginate.return_value = [{"NetworkAcls": [nacl]}]
    mock_ec2.describe_network_acls.return_value = {"NetworkAcls": [nacl]}
    mock_next_free.side_effect = [99, 98]  # first choice collides, second is fresh
    mock_create_entry.side_effect = [
        ClientError({"Error": {"Code": "NetworkAclEntryAlreadyExists", "Message": "x"}}, "CreateNetworkAclEntry"),
        None,
    ]
    mock_dynamo.exceptions = MagicMock()

    with patch("GDPatrol.lambda_function.acquire_lock"), patch("GDPatrol.lambda_function.release_lock"):
        result = blacklist_ip("10.0.0.1")

    assert result is True
    assert mock_create_entry.call_args_list[0].args[2] == 99
    assert mock_create_entry.call_args_list[1].args[2] == 98


# --- _next_free_ingress_deny_rule_number tests ---


def _acl_entry(rule_number, egress=False, action="deny", cidr="1.2.3.4/32"):
    return {"RuleNumber": rule_number, "Egress": egress, "RuleAction": action, "CidrBlock": cidr}


def test_next_free_rule_number_empty_nacl():
    """With no entries at all, the first GDPatrol deny rule starts at 100."""
    assert _next_free_ingress_deny_rule_number([]) == 100


def test_next_free_rule_number_prefers_one_below_lowest_deny():
    """The decrement scheme: a new rule goes one below the current lowest GDPatrol deny rule."""
    entries = [_acl_entry(50)]
    assert _next_free_ingress_deny_rule_number(entries) == 49


def test_next_free_rule_number_skips_allow_rule_collision():
    """A pre-existing ALLOW rule at the preferred slot must not be evicted or collided with."""
    entries = [_acl_entry(50), _acl_entry(49, action="allow", cidr="0.0.0.0/0")]
    assert _next_free_ingress_deny_rule_number(entries) == 48


def test_next_free_rule_number_ignores_egress_entries():
    """Egress and ingress rule numbers are independent namespaces; an egress rule must not block ingress."""
    entries = [_acl_entry(50), _acl_entry(49, egress=True, action="allow", cidr="0.0.0.0/0")]
    assert _next_free_ingress_deny_rule_number(entries) == 49


def test_next_free_rule_number_low_end_exhaustion_falls_back_to_high_range():
    """When the lowest deny rule is 1, decrementing below it is impossible; search the high end instead."""
    entries = [_acl_entry(1)]
    assert _next_free_ingress_deny_rule_number(entries) == 32766


def test_next_free_rule_number_low_range_fully_occupied_falls_back_to_high_range():
    """Even if the preferred slot isn't literally 0, a fully-occupied low range must fall back high."""
    entries = [_acl_entry(3)] + [_acl_entry(n, action="allow", cidr="0.0.0.0/0") for n in (1, 2)]
    assert _next_free_ingress_deny_rule_number(entries) == 32766


def test_next_free_rule_number_high_range_skips_occupied_slots():
    """The high-end search must also skip numbers that are already taken."""
    entries = [_acl_entry(1), _acl_entry(32766, action="allow", cidr="0.0.0.0/0")]
    assert _next_free_ingress_deny_rule_number(entries) == 32765


def test_next_free_rule_number_fully_occupied_nacl_returns_none():
    """A NACL with every ingress rule number taken must return None so the caller triggers cleanup."""
    entries = [_acl_entry(n) for n in range(1, 32767)]
    assert _next_free_ingress_deny_rule_number(entries) is None


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
    # New rules get decreasing numbers, so the HIGHEST rule number is the oldest.
    assert call_kwargs["RuleNumber"] == 20


@patch("GDPatrol.lambda_function.dynamodb_client")
@patch("GDPatrol.lambda_function.ec2_client")
def test_delete_oldest_acl_entry_fallback_excludes_non_gdpatrol_rules(mock_ec2, mock_dynamo):
    """Only /32 GDPatrol-managed deny rules are candidates for deletion — the implicit
    default-deny (0.0.0.0/0 @ 32767) and customer subnet-level denies must be left alone."""
    mock_dynamo.query.return_value = {"Items": []}
    mock_ec2.describe_network_acls.return_value = {
        "NetworkAcls": [
            {
                "Entries": [
                    {"Egress": False, "RuleAction": "deny", "RuleNumber": 10, "CidrBlock": "1.2.3.4/32"},
                    {"Egress": False, "RuleAction": "deny", "RuleNumber": 32767, "CidrBlock": "0.0.0.0/0"},
                    {"Egress": False, "RuleAction": "deny", "RuleNumber": 5, "CidrBlock": "10.0.0.0/24"},
                ]
            }
        ]
    }

    delete_oldest_acl_entry("acl-123")

    mock_ec2.delete_network_acl_entry.assert_called_once()
    call_kwargs = mock_ec2.delete_network_acl_entry.call_args[1]
    assert call_kwargs["RuleNumber"] == 10  # the only /32 GDPatrol-managed rule


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


@patch("GDPatrol.lambda_function.dynamodb_client")
@patch("GDPatrol.lambda_function.ec2_client")
def test_delete_oldest_acl_entry_reconciles_stale_dynamodb_row(mock_ec2, mock_dynamo):
    """If AWS no longer has the tracked rule, the stale DynamoDB row must still be deleted so it
    doesn't keep winning as 'oldest' forever."""
    from botocore.exceptions import ClientError

    mock_dynamo.query.return_value = {
        "Items": [{"network_acl_id": {"S": "acl-123"}, "created_at": {"S": "1000.0"}, "rule_number": {"S": "50"}}]
    }
    mock_ec2.delete_network_acl_entry.side_effect = ClientError(
        {"Error": {"Code": "InvalidNetworkAclEntry.NotFound", "Message": "not found"}}, "DeleteNetworkAclEntry"
    )

    delete_oldest_acl_entry("acl-123")

    mock_dynamo.delete_item.assert_called_once_with(
        TableName="GDPatrol",
        Key={"network_acl_id": {"S": "acl-123"}, "created_at": {"S": "1000.0"}},
    )


@patch("GDPatrol.lambda_function.dynamodb_client")
@patch("GDPatrol.lambda_function.ec2_client")
def test_delete_oldest_acl_entry_other_errors_do_not_touch_dynamodb(mock_ec2, mock_dynamo):
    """A non-NotFound AWS error must not be treated as drift — the DynamoDB row must survive for retry."""
    from botocore.exceptions import ClientError

    mock_dynamo.query.return_value = {
        "Items": [{"network_acl_id": {"S": "acl-123"}, "created_at": {"S": "1000.0"}, "rule_number": {"S": "50"}}]
    }
    mock_ec2.delete_network_acl_entry.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "nope"}}, "DeleteNetworkAclEntry"
    )

    delete_oldest_acl_entry("acl-123")

    mock_dynamo.delete_item.assert_not_called()


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


@patch("GDPatrol.lambda_function.time.sleep", return_value=None)
@patch("GDPatrol.lambda_function.dynamodb_client")
def test_acquire_lock_queues_through_a_burst(mock_dynamo, mock_sleep):
    """A burst of contention must queue past the old 5-attempt budget instead of failing to acquire."""
    busy_attempts = 10  # more than the old default max_retries of 5
    call_count = {"n": 0}

    def get_item_side_effect(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] <= busy_attempts:
            return {"Item": {"timestamp": {"S": str(int(time.time()))}}}
        return {}

    mock_dynamo.get_item.side_effect = get_item_side_effect
    mock_dynamo.exceptions = MagicMock()
    mock_dynamo.exceptions.ConditionalCheckFailedException = type("ConditionalCheckFailedException", (Exception,), {})

    acquire_lock("GDPatrol_lock", "gdpatrol-nacl")

    mock_dynamo.put_item.assert_called_once()


@patch("GDPatrol.lambda_function.release_lock")
@patch("GDPatrol.lambda_function.acquire_lock")
def test_blacklist_ip_uses_shared_lock_id(mock_acquire, mock_release):
    """Two different IPs must serialize on the SAME lock id, not per-IP locks, since blacklist_ip mutates every NACL."""
    mock_acquire.side_effect = Exception("boom")
    blacklist_ip("10.0.0.1")
    blacklist_ip("10.0.0.2")

    lock_ids_used = {call.args[1] for call in mock_acquire.call_args_list}
    assert lock_ids_used == {"gdpatrol-nacl"}


@patch("GDPatrol.lambda_function.release_lock")
@patch("GDPatrol.lambda_function.acquire_lock")
def test_whitelist_ip_uses_lock(mock_acquire, mock_release, mock_ec2_client):
    """whitelist_ip must serialize its NACL mutations under the same shared lock as blacklist_ip."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])

    whitelist_ip("192.168.1.1")

    mock_acquire.assert_called_once_with(os.environ.get("GD_PATROL_LOCK_TABLE", "GDPatrol_lock"), "gdpatrol-nacl")
    mock_release.assert_called_once()


@patch("GDPatrol.lambda_function.release_lock")
@patch("GDPatrol.lambda_function.acquire_lock")
def test_whitelist_ip_no_release_when_acquire_fails(mock_acquire, mock_release):
    """A failed acquire_lock must not release another invocation's lock."""
    mock_acquire.side_effect = Exception("Unable to acquire lock after multiple attempts")
    assert whitelist_ip("198.51.100.1") is False
    mock_release.assert_not_called()


# --- whitelist_ip tests ---


def test_whitelist_ip(mock_ec2_client, mock_dynamodb_client):
    """Test whitelisting (removing) an IP from NACLs."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    nacl = mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    nacl_id = nacl["NetworkAcl"]["NetworkAclId"]
    create_lock_table(mock_dynamodb_client)

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


def test_whitelist_ip_invalid_ip_returns_false():
    """An invalid IP must be rejected before touching any NACLs."""
    assert whitelist_ip("not-an-ip") is False


def test_whitelist_ip_no_matching_rules_returns_false(mock_ec2_client, mock_dynamodb_client):
    """Whitelisting an IP with no matching rule anywhere is a no-op and must return False, not True."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    create_lock_table(mock_dynamodb_client)

    assert whitelist_ip("203.0.113.200") is False


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

    # Verify the instance's (only) network interface has the quarantine security group
    instance_desc = mock_ec2_client.describe_instances(InstanceIds=[instance_id])
    nics = instance_desc["Reservations"][0]["Instances"][0]["NetworkInterfaces"]
    assert len(nics) == 1
    assert any("Quarantine" in g["GroupName"] for g in nics[0]["Groups"])


def test_quarantine_instance_isolates_every_eni(mock_ec2_client):
    """An instance with multiple ENIs must have the quarantine SG applied to ALL of them, not just the primary."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    subnet = mock_ec2_client.create_subnet(VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.1.0/24")
    instance = mock_ec2_client.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet["Subnet"]["SubnetId"],
    )
    instance_id = instance["Instances"][0]["InstanceId"]

    second_eni = mock_ec2_client.create_network_interface(SubnetId=subnet["Subnet"]["SubnetId"])["NetworkInterface"]
    mock_ec2_client.attach_network_interface(NetworkInterfaceId=second_eni["NetworkInterfaceId"], InstanceId=instance_id, DeviceIndex=1)

    result = quarantine_instance(instance_id, vpc["Vpc"]["VpcId"])
    assert result is True

    instance_desc = mock_ec2_client.describe_instances(InstanceIds=[instance_id])
    nics = instance_desc["Reservations"][0]["Instances"][0]["NetworkInterfaces"]
    assert len(nics) == 2
    for nic in nics:
        assert any("Quarantine" in g["GroupName"] for g in nic["Groups"]), f"ENI {nic['NetworkInterfaceId']} was not quarantined"


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


def test_asg_detach_instance_missing_instance_id_returns_false():
    """A falsy instance_id must be rejected before making any AWS calls."""
    assert asg_detach_instance(None) is False
    assert asg_detach_instance("") is False


def test_asg_detach_instance_no_asg_membership_returns_false(aws_credentials):
    """An instance not in any ASG is a no-op and must not be reported as a successful action."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.1.0/24")
        instance = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet["Subnet"]["SubnetId"],
        )
        instance_id = instance["Instances"][0]["InstanceId"]

        assert asg_detach_instance(instance_id) is False


def test_asg_detach_instance_detaches_when_in_asg(aws_credentials):
    """When the instance IS in an ASG, detaching returns True and actually removes it from the ASG."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        autoscaling = boto3.client("autoscaling", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.1.0/24")

        autoscaling.create_launch_configuration(LaunchConfigurationName="lc1", ImageId="ami-12345678", InstanceType="t2.micro")
        autoscaling.create_auto_scaling_group(
            AutoScalingGroupName="asg1",
            LaunchConfigurationName="lc1",
            MinSize=0,
            MaxSize=2,
            DesiredCapacity=1,
            VPCZoneIdentifier=subnet["Subnet"]["SubnetId"],
        )
        group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=["asg1"])["AutoScalingGroups"][0]
        instance_id = group["Instances"][0]["InstanceId"]

        assert asg_detach_instance(instance_id) is True

        remaining = autoscaling.describe_auto_scaling_instances(InstanceIds=[instance_id])["AutoScalingInstances"]
        assert remaining == []


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
