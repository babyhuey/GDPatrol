import pytest
import json
import logging
import time
import socket
from unittest.mock import patch, MagicMock
import sys
import os
from pathlib import Path

# Add the parent directory to sys.path to import the lambda function
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import GDPatrol.lambda_function as lambda_module
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
    resolve_domain_a_records,
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


def test_get_reliability_fallback_logs_warning(caplog):
    """Falling back to the default reliability of 5 for an unknown finding type must log a
    warning, so a typo'd finding type in config.json is visible instead of silently under-gating."""
    test_config_path = Path(__file__).parent / "test_config.json"
    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()
        config = Config("TotallyUnknownFindingType")
        with caplog.at_level(logging.WARNING):
            reliability = config.get_reliability()

    assert reliability == 5
    assert any("TotallyUnknownFindingType" in record.message for record in caplog.records)


def test_real_config_actions_are_all_lists():
    """Every playbook entry in the real config.json must use list-form actions.

    Regression test for config.json's Persistence:IAMUser/NetworkPermissions entry,
    which held actions as a bare string ("disable_sg_access") instead of a list.
    """
    real_config_path = Path(__file__).parent.parent / "GDPatrol" / "config.json"
    data = json.loads(real_config_path.read_text())
    for playbook in data["playbooks"]["playbook"]:
        assert isinstance(playbook["actions"], list), f"{playbook['type']} actions is not a list"


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
    # Prompt is status-aware so the AI recommends follow-up, not actions GDPatrol already took.
    prompt_text = call_body["messages"][0]["content"]
    assert "remediated" in prompt_text and "no-playbook" in prompt_text
    assert "do NOT recommend actions GDPatrol already performed" in prompt_text

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


def test_aggressive_cleanup_scales_with_configured_limit(mock_ec2_client, mock_dynamodb_client):
    """The cleanup trigger (limit-1) and keep-count (limit//2) follow NACL_RULE_LIMIT."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    nacl_id = mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])["NetworkAcl"]["NetworkAclId"]
    create_gdpatrol_table(mock_dynamodb_client)
    create_lock_table(mock_dynamodb_client)
    # Seed 5 GDPatrol /32 deny rules. With NACL_RULE_LIMIT=6 the trigger is >=5, so
    # blocking one more fires aggressive cleanup (keep 6//2=3, evict the rest).
    for i, rn in enumerate(range(100, 95, -1)):
        mock_ec2_client.create_network_acl_entry(
            CidrBlock=f"10.0.0.{i}/32", Egress=False, NetworkAclId=nacl_id, Protocol="-1", RuleAction="deny", RuleNumber=rn
        )
    with patch("GDPatrol.lambda_function.NACL_RULE_LIMIT", 6):
        assert blacklist_ip("203.0.113.50") is True
    deny = [
        e
        for e in mock_ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]["Entries"]
        if not e["Egress"] and e["RuleAction"] == "deny" and e.get("CidrBlock", "").endswith("/32")
    ]
    # Without cleanup it would be 6 (5 old + new); cleanup kept 3 old + added the new = 4.
    assert len(deny) <= 4, f"cleanup did not cap to the configured limit: {len(deny)} rules"
    assert any(e["CidrBlock"] == "203.0.113.50/32" for e in deny)


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


def test_delete_dynamodb_rule_entries_skips_malformed_items(mock_dynamodb_client):
    """A legacy item without rule_number must not abort cleanup of valid items after it."""
    create_gdpatrol_table(mock_dynamodb_client)
    # created_at "100.0" sorts before "50.0" lexicographically, so the malformed
    # item is encountered first
    mock_dynamodb_client.put_item(
        TableName="GDPatrol",
        Item={"network_acl_id": {"S": "acl-123"}, "created_at": {"S": "100.0"}},
    )
    mock_dynamodb_client.put_item(
        TableName="GDPatrol",
        Item={"network_acl_id": {"S": "acl-123"}, "created_at": {"S": "50.0"}, "rule_number": {"S": "50"}},
    )

    delete_dynamodb_rule_entries("acl-123", {50})

    items = mock_dynamodb_client.scan(TableName="GDPatrol")["Items"]
    assert len(items) == 1
    assert "rule_number" not in items[0]


def test_whitelist_ip_partial_failure_still_cleans_dynamodb(mock_ec2_client, mock_dynamodb_client, monkeypatch):
    """One failed rule delete reports failure but doesn't block cleanup for the rest."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    create_gdpatrol_table(mock_dynamodb_client)
    create_lock_table(mock_dynamodb_client)

    assert blacklist_ip("203.0.113.88") is True
    assert mock_dynamodb_client.scan(TableName="GDPatrol")["Count"] >= 2

    real_delete = lambda_module.ec2_client.delete_network_acl_entry
    calls = {"count": 0}

    def flaky_delete(**kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise Exception("InvalidNetworkAclEntry.NotFound")
        return real_delete(**kwargs)

    monkeypatch.setattr(lambda_module.ec2_client, "delete_network_acl_entry", flaky_delete)

    assert whitelist_ip("203.0.113.88") is False
    # Only the rule whose delete failed keeps its DynamoDB entry
    assert mock_dynamodb_client.scan(TableName="GDPatrol")["Count"] == 1


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
        # RDS finding with severity 4 + reliability 5 = 9, below the gate, won't execute
        sample_rds_guardduty_event["severity"] = 4
        lambda_handler(sample_rds_guardduty_event, None)
        mock_blacklist.assert_not_called()

        # Exactly at the boundary (severity 5 + reliability 5 = 10) now triggers under the >= gate
        sample_rds_guardduty_event["severity"] = 5
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


def test_blacklist_ip_aggressive_cleanup_never_deletes_customer_rule(mock_ec2_client, mock_dynamodb_client):
    """Aggressive cleanup must only ever consider GDPatrol-managed (/32 ingress deny) rules —
    a customer's own deny rule (e.g. a subnet-level block) must never be swept up, even when it
    pushes the NACL's total deny-rule count over the cleanup threshold."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    nacl = mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    nacl_id = nacl["NetworkAcl"]["NetworkAclId"]
    create_gdpatrol_table(mock_dynamodb_client)
    create_lock_table(mock_dynamodb_client)

    # Customer's own subnet-level deny rule — GDPatrol must never touch this.
    mock_ec2_client.create_network_acl_entry(
        CidrBlock="10.0.0.0/24", Egress=False, NetworkAclId=nacl_id, Protocol="-1", RuleAction="deny", RuleNumber=500
    )
    # 19 GDPatrol-managed /32 deny rules, enough to trigger the aggressive-cleanup threshold.
    for i in range(1, 20):
        mock_ec2_client.create_network_acl_entry(
            CidrBlock=f"10.1.0.{i}/32", Egress=False, NetworkAclId=nacl_id, Protocol="-1", RuleAction="deny", RuleNumber=i
        )

    assert blacklist_ip("203.0.113.50") is True

    entries = mock_ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]["Entries"]
    assert any(e["RuleNumber"] == 500 and e.get("CidrBlock") == "10.0.0.0/24" for e in entries), (
        "customer's own deny rule was swept up by aggressive cleanup"
    )


def test_blacklist_ip_aggressive_cleanup_orders_by_created_at_not_rule_number(mock_ec2_client, mock_dynamodb_client):
    """Aggressive cleanup must evict the oldest rules by DynamoDB created_at, not by rule number —
    the allocator can hand a high rule number to a brand-new rule once the low range is exhausted,
    so 'lowest rule number' no longer means 'newest'."""
    vpc = mock_ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    nacl = mock_ec2_client.create_network_acl(VpcId=vpc["Vpc"]["VpcId"])
    nacl_id = nacl["NetworkAcl"]["NetworkAclId"]
    create_gdpatrol_table(mock_dynamodb_client)
    create_lock_table(mock_dynamodb_client)

    def add_tracked_rule(rule_number, created_at, cidr):
        mock_ec2_client.create_network_acl_entry(
            CidrBlock=cidr, Egress=False, NetworkAclId=nacl_id, Protocol="-1", RuleAction="deny", RuleNumber=rule_number
        )
        mock_dynamodb_client.put_item(
            TableName="GDPatrol",
            Item={
                "network_acl_id": {"S": nacl_id},
                "created_at": {"S": created_at},
                "rule_number": {"S": str(rule_number)},
            },
        )

    # Oldest rule holds a LOW rule number.
    add_tracked_rule(5, "1.0", "10.1.0.5/32")
    # Newest rule holds a HIGH rule number, as the allocator hands out once the low range is exhausted.
    add_tracked_rule(32760, "300.0", "10.1.0.250/32")
    # 17 filler rules in between, to reach the 19-rule cleanup threshold.
    for i in range(17):
        add_tracked_rule(101 + i, str(200 + i), f"10.1.1.{i}/32")

    assert blacklist_ip("203.0.113.60") is True

    entries = mock_ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]["Entries"]
    rule_numbers = {e["RuleNumber"] for e in entries if not e["Egress"] and e["RuleAction"] == "deny"}
    assert 32760 in rule_numbers, "newest rule (high rule number) was wrongly evicted"
    assert 5 not in rule_numbers, "oldest rule (low rule number) should have been evicted, not kept"


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


def test_disable_account_skips_protected_user(aws_credentials):
    """A protected user must never be auto-disabled — no policy attached, returns False."""
    import boto3
    from moto import mock_aws

    with mock_aws(), patch("GDPatrol.lambda_function.PROTECTED_USERS", {"protecteduser", "root"}):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="protecteduser")
        assert disable_account("protecteduser") is False
        assert disable_ec2_access("protecteduser") is False
        assert disable_sg_access("protecteduser") is False
        assert iam.list_user_policies(UserName="protecteduser")["PolicyNames"] == []


def test_root_is_always_protected():
    """root must be protected even when GD_PATROL_PROTECTED_USERS is unset."""
    from GDPatrol.lambda_function import PROTECTED_USERS

    assert "root" in PROTECTED_USERS


def _published_field(mock_publish, title):
    """Extract a Slack field value from the payload passed to publish_message."""
    payload = json.loads(mock_publish.call_args[0][1])
    for f in payload["attachments"][0]["fields"]:
        if f["title"] == title:
            return f["value"]
    return None


def _rds_ip_event(finding_type, severity):
    return {
        "id": "t",
        "type": finding_type,
        "severity": severity,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {"resourceType": "RDSDBInstance", "rdsDbInstanceDetails": {"dbInstanceIdentifier": "db", "engine": "mysql"}},
        "service": {
            "action": {"actionType": "RDS_LOGIN_ATTEMPT", "rdsLoginAttemptAction": {"remoteIpDetails": {"ipAddressV4": "203.0.113.5"}}},
            "count": 1,
            "eventFirstSeen": "x",
            "eventLastSeen": "y",
        },
        "description": "d",
    }


def test_slack_fields_remediated(monkeypatch):
    """A fully-executed playbook yields Status 'remediated' and a concrete Auto-remediation line."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")
    event = _rds_ip_event("TestIPFinding", 8)
    config_data = {"playbooks": {"playbook": [{"type": "TestIPFinding", "actions": ["blacklist_ip"], "reliability": 5}]}}
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message") as mock_publish,
        patch("GDPatrol.lambda_function.blacklist_ip", return_value=True),
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(config_data)
        lambda_handler(event, None)
    assert _published_field(mock_publish, "Status") == "remediated"
    auto = _published_field(mock_publish, "Auto-remediation")
    assert "blacklist_ip" in auto and "203.0.113.5" in auto and "completed" in auto


def test_slack_fields_needs_review(monkeypatch):
    """A playbook that doesn't fully fire (below the gate) yields Status 'needs-review'."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")
    # sev 6 disable_account: below the strict gate (needs sev >= 7), so it does not fire.
    event = {
        "id": "t",
        "type": "TestIAMFinding",
        "severity": 6,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {"resourceType": "AccessKey", "accessKeyDetails": {"userName": "baduser"}},
        "service": {
            "action": {"actionType": "AWS_API_CALL", "awsApiCallAction": {}},
            "count": 1,
            "eventFirstSeen": "x",
            "eventLastSeen": "y",
        },
        "description": "d",
    }
    config_data = {"playbooks": {"playbook": [{"type": "TestIAMFinding", "actions": ["disable_account"], "reliability": 10}]}}
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message") as mock_publish,
        patch("GDPatrol.lambda_function.disable_account") as mock_disable,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(config_data)
        lambda_handler(event, None)
        mock_disable.assert_not_called()
    assert _published_field(mock_publish, "Status") == "needs-review"
    assert "below action threshold or protected target" in _published_field(mock_publish, "Auto-remediation")


def test_slack_fields_no_playbook(monkeypatch):
    """A finding type with no playbook yields Status 'no-playbook' and no auto-remediation."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")
    event = _rds_ip_event("UnconfiguredFinding", 8)
    config_data = {"playbooks": {"playbook": []}}
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message") as mock_publish,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(config_data)
        lambda_handler(event, None)
    assert _published_field(mock_publish, "Status") == "no-playbook"
    assert "no playbook" in _published_field(mock_publish, "Auto-remediation")


def test_no_slack_alert_for_low_severity_skipped_playbook(monkeypatch):
    """A low-severity finding whose playbook is skipped by the execution gate does not
    alert — the skip is by design (e.g. Recon:EC2/PortProbeUnprotectedPort at severity 2),
    not a remediation failure."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")
    # severity 2 + reliability 5 = 7, below the >= 10 gate: blacklist_ip is skipped
    event = _rds_ip_event("TestIPFinding", 2)
    config_data = {"playbooks": {"playbook": [{"type": "TestIPFinding", "actions": ["blacklist_ip"], "reliability": 5}]}}
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message") as mock_publish,
        patch("GDPatrol.lambda_function.blacklist_ip") as mock_blacklist,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(config_data)
        lambda_handler(event, None)
        mock_blacklist.assert_not_called()
    mock_publish.assert_not_called()


def test_no_slack_alert_at_severity_five(monkeypatch):
    """Severity 5 exactly is below the strictly-greater-than notify threshold."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")
    event = _rds_ip_event("UnconfiguredFinding", 5)
    config_data = {"playbooks": {"playbook": []}}
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message") as mock_publish,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(config_data)
        lambda_handler(event, None)
    mock_publish.assert_not_called()


def test_slack_alert_when_attempted_action_fails(monkeypatch):
    """An action that was attempted but failed still alerts even below severity 5."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")
    # severity 4 + reliability 8 = 12, above the gate: blacklist_ip is attempted and fails
    event = _rds_ip_event("TestIPFinding", 4)
    config_data = {"playbooks": {"playbook": [{"type": "TestIPFinding", "actions": ["blacklist_ip"], "reliability": 8}]}}
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message") as mock_publish,
        patch("GDPatrol.lambda_function.blacklist_ip", return_value=False),
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(config_data)
        lambda_handler(event, None)
    mock_publish.assert_called_once()
    assert _published_field(mock_publish, "Status") == "needs-review"


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
        # severity 2 + reliability 5 = 7, not >= 10, but count 200 > 100
        mock_blacklist.assert_called_once_with("1.2.3.4")


def test_lambda_handler_blacklist_domain_count_threshold(monkeypatch):
    """blacklist_domain must also bypass the reliability gate when count > 100, matching blacklist_ip."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-domain-id",
        "type": "SomeDomainFinding",
        "severity": 2,
        "accountId": "123456789012",
        "region": "us-east-1",
        "service": {
            "action": {
                "actionType": "DNS_REQUEST",
                "dnsRequestAction": {"domain": "malicious.example.com"},
            },
            "count": 200,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "DNS beacon",
    }
    config_data = {"playbooks": {"playbook": [{"type": "SomeDomainFinding", "actions": ["blacklist_domain"], "reliability": 5}]}}

    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message"),
        patch("GDPatrol.lambda_function.resolve_domain_a_records", return_value=["1.2.3.4"]),
        patch("GDPatrol.lambda_function.blacklist_ip") as mock_blacklist,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(config_data)
        mock_blacklist.return_value = True
        lambda_handler(event, None)
        # severity 2 + reliability 5 = 7, not >= 10, but count 200 > 100
        mock_blacklist.assert_called_once_with("1.2.3.4")


def test_lambda_handler_disable_account_blocked_below_severity_floor(monkeypatch):
    """disable_account's strict gate requires severity >= 7 regardless of how high the combined
    score is — a sev-6 finding must not disable an account even with reliability 10 (sum 16)."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-id",
        "type": "SomeIAMFinding",
        "severity": 6,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {"userName": "baduser"},
        },
        "service": {
            "action": {"actionType": "AWS_API_CALL", "awsApiCallAction": {}},
            "count": 1,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "IAM finding",
    }
    config_data = {"playbooks": {"playbook": [{"type": "SomeIAMFinding", "actions": ["disable_account"], "reliability": 10}]}}

    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message"),
        patch("GDPatrol.lambda_function.disable_account") as mock_disable,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(config_data)
        lambda_handler(event, None)
        mock_disable.assert_not_called()


def test_lambda_handler_disable_account_fires_when_sum_exceeds_threshold(monkeypatch):
    """disable_account must fire once severity >= 7 AND severity + reliability > 13."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-id",
        "type": "SomeIAMFinding",
        "severity": 7,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {"userName": "baduser"},
        },
        "service": {
            "action": {"actionType": "AWS_API_CALL", "awsApiCallAction": {}},
            "count": 1,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "IAM finding",
    }
    # severity 7 + reliability 7 = 14, > 13
    config_data = {"playbooks": {"playbook": [{"type": "SomeIAMFinding", "actions": ["disable_account"], "reliability": 7}]}}

    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message"),
        patch("GDPatrol.lambda_function.disable_account") as mock_disable,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(config_data)
        mock_disable.return_value = True
        lambda_handler(event, None)
        mock_disable.assert_called_once_with("baduser")


def test_lambda_handler_disable_account_strict_boundary_is_exclusive(monkeypatch):
    """The disable_account combined-score gate is strict (>), not >=: severity + reliability == 13
    must NOT fire, while == 14 must. Guards against an accidental future switch to >=."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    def make_event(severity):
        return {
            "id": "test-id",
            "type": "SomeIAMFinding",
            "severity": severity,
            "accountId": "123456789012",
            "region": "us-east-1",
            "resource": {"resourceType": "AccessKey", "accessKeyDetails": {"userName": "baduser"}},
            "service": {
                "action": {"actionType": "AWS_API_CALL", "awsApiCallAction": {}},
                "count": 1,
                "eventFirstSeen": "2024-01-01T00:00:00Z",
                "eventLastSeen": "2024-01-01T00:00:00Z",
            },
            "description": "IAM finding",
        }

    # reliability 6: at severity 7.0 the sum is exactly 13 (severity floor met, but 13 is not > 13).
    config_data = {"playbooks": {"playbook": [{"type": "SomeIAMFinding", "actions": ["disable_account"], "reliability": 6}]}}

    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message"),
        patch("GDPatrol.lambda_function.disable_account") as mock_disable,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(config_data)
        mock_disable.return_value = True

        # severity 7.0 + reliability 6 == 13, NOT > 13 -> must not fire
        lambda_handler(make_event(7.0), None)
        mock_disable.assert_not_called()

        # severity 8.0 + reliability 6 == 14 > 13 -> must fire
        lambda_handler(make_event(8.0), None)
        mock_disable.assert_called_once_with("baduser")


def test_lambda_handler_raised_iam_entry_fires_at_high_severity(monkeypatch):
    """A raised high-confidence IAM entry (InstanceCredentialExfiltration, reliability 8) must
    auto-disable at a genuine High severity of 7.0 (7 >= 7 and 7 + 8 = 15 > 13)."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-id",
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        "severity": 7.0,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {"resourceType": "AccessKey", "accessKeyDetails": {"userName": "baduser"}},
        "service": {
            "action": {"actionType": "AWS_API_CALL", "awsApiCallAction": {}},
            "count": 1,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "Credential exfiltration",
    }

    # Use the REAL config.json so the raised reliability (8) for this type is what's exercised.
    real_config_path = Path(__file__).parent.parent / "GDPatrol" / "config.json"
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message"),
        patch("GDPatrol.lambda_function.disable_account") as mock_disable,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = real_config_path.read_text()
        mock_disable.return_value = True
        lambda_handler(event, None)
        mock_disable.assert_called_once_with("baduser")


def test_lambda_handler_strict_gate_isolated_to_disable_account(monkeypatch):
    """The strict severity>=7 gate is scoped to disable_account only: a severity-6 finding whose
    playbook has both disable_account and blacklist_ip must NOT disable the account (6 < 7) but
    must still run blacklist_ip (6 + reliability 8 = 14 >= 10)."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-id",
        "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
        "severity": 6,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {"resourceType": "AccessKey", "accessKeyDetails": {"userName": "baduser"}},
        "service": {
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {"remoteIpDetails": {"ipAddressV4": "9.8.7.6"}},
            },
            "count": 1,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "IAM malicious caller",
    }

    # Real config: this type has actions [disable_account, blacklist_ip] at reliability 8.
    real_config_path = Path(__file__).parent.parent / "GDPatrol" / "config.json"
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message"),
        patch("GDPatrol.lambda_function.disable_account") as mock_disable,
        patch("GDPatrol.lambda_function.blacklist_ip") as mock_blacklist,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = real_config_path.read_text()
        mock_blacklist.return_value = True
        lambda_handler(event, None)
        mock_disable.assert_not_called()
        mock_blacklist.assert_called_once_with("9.8.7.6")


def test_lambda_handler_no_notify_when_action_skipped_by_gate(monkeypatch):
    """A low-severity finding whose configured playbook is skipped by the execution gate
    must NOT notify — the skip is intentional, so there is nothing for a human to review."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-id",
        "type": "Discovery:RDS/MaliciousIPCaller",
        "severity": 3,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {
            "resourceType": "RDSDBInstance",
            "rdsDbInstanceDetails": {"dbInstanceIdentifier": "testdb", "engine": "mysql"},
        },
        "service": {
            "action": {
                "actionType": "RDS_LOGIN_ATTEMPT",
                "rdsLoginAttemptAction": {"remoteIpDetails": {"ipAddressV4": "1.2.3.4"}},
            },
            "count": 1,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "RDS finding",
    }

    # test_config.json reliability for this type is 5; severity 3 + 5 = 8, below the >=10 gate,
    # so the one configured action never fires — and no Slack message goes out.
    test_config_path = Path(__file__).parent / "test_config.json"
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message") as mock_publish,
        patch("GDPatrol.lambda_function.blacklist_ip") as mock_blacklist,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()
        lambda_handler(event, None)

        mock_blacklist.assert_not_called()
        mock_publish.assert_not_called()


def test_lambda_handler_status_field_remediated_when_all_actions_succeed(monkeypatch):
    """When every configured action executes and succeeds, the Status field reads 'remediated'."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-id",
        "type": "Discovery:RDS/MaliciousIPCaller",
        "severity": 8,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {
            "resourceType": "RDSDBInstance",
            "rdsDbInstanceDetails": {"dbInstanceIdentifier": "testdb", "engine": "mysql"},
        },
        "service": {
            "action": {
                "actionType": "RDS_LOGIN_ATTEMPT",
                "rdsLoginAttemptAction": {"remoteIpDetails": {"ipAddressV4": "1.2.3.4"}},
            },
            "count": 1,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "RDS finding",
    }

    test_config_path = Path(__file__).parent / "test_config.json"
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message") as mock_publish,
        patch("GDPatrol.lambda_function.blacklist_ip", return_value=True),
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()
        lambda_handler(event, None)

        published = json.loads(mock_publish.call_args[0][1])
        fields = published["attachments"][0]["fields"]
        status_field = next(f for f in fields if f["title"] == "Status")
        assert status_field["value"] == "remediated"


def test_lambda_handler_status_field_no_playbook_when_no_actions_configured(monkeypatch):
    """A finding type with no configured playbook actions must report 'no-playbook'."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-id",
        "type": "NoPlaybookConfigured",
        "severity": 6,
        "accountId": "123456789012",
        "region": "us-east-1",
        "service": {
            "action": {},
            "count": 1,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "Unhandled finding type",
    }

    test_config_path = Path(__file__).parent / "test_config.json"
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message") as mock_publish,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()
        lambda_handler(event, None)

        published = json.loads(mock_publish.call_args[0][1])
        fields = published["attachments"][0]["fields"]
        status_field = next(f for f in fields if f["title"] == "Status")
        assert status_field["value"] == "no-playbook"


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
        # Add the IAM finding type to the mock config. disable_account's strict gate needs
        # severity >= 7 (met: 8) AND severity + reliability > 13, so reliability 6 (sum 14) is used.
        config_data = json.loads(test_config_path.read_text())
        config_data["playbooks"]["playbook"].append(
            {
                "type": "Recon:IAMUser/MaliciousIPCaller",
                "actions": ["disable_account"],
                "reliability": 6,
            }
        )
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(config_data)
        mock_disable.return_value = True
        lambda_handler(event, None)
        mock_disable.assert_called_once_with("baduser")


def test_lambda_handler_fractional_severity_crosses_gate(monkeypatch):
    """A fractional severity like 5.5 must not be truncated to 5, which would under-count the reliability gate."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-id",
        "type": "Discovery:RDS/MaliciousIPCaller",
        "severity": 5.5,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {
            "resourceType": "RDSDBInstance",
            "rdsDbInstanceDetails": {"dbInstanceIdentifier": "testdb", "engine": "mysql"},
        },
        "service": {
            "action": {
                "actionType": "RDS_LOGIN_ATTEMPT",
                "rdsLoginAttemptAction": {"remoteIpDetails": {"ipAddressV4": "1.2.3.4"}},
            },
            "count": 1,
            "eventFirstSeen": "2024-01-01T00:00:00Z",
            "eventLastSeen": "2024-01-01T00:00:00Z",
        },
        "description": "RDS finding",
    }

    # test_config.json reliability for this type is 5. int(5.5) + 5 = 10, NOT > 10 (bug);
    # float(5.5) + 5 = 10.5 > 10 (fixed) — must trigger blacklist_ip.
    test_config_path = Path(__file__).parent / "test_config.json"
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message"),
        patch("GDPatrol.lambda_function.blacklist_ip") as mock_blacklist,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()
        mock_blacklist.return_value = True
        lambda_handler(event, None)
        mock_blacklist.assert_called_once_with("1.2.3.4")


def test_lambda_handler_survives_missing_slack_fields(monkeypatch):
    """Missing service.count/eventFirstSeen/eventLastSeen must not crash the handler after actions have run."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-id",
        "type": "Discovery:RDS/MaliciousIPCaller",
        "severity": 8,
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {
            "resourceType": "RDSDBInstance",
            "rdsDbInstanceDetails": {"dbInstanceIdentifier": "testdb", "engine": "mysql"},
        },
        "service": {
            "action": {
                "actionType": "RDS_LOGIN_ATTEMPT",
                "rdsLoginAttemptAction": {"remoteIpDetails": {"ipAddressV4": "1.2.3.4"}},
            },
            # count, eventFirstSeen, eventLastSeen intentionally omitted
        },
        "description": "RDS finding",
    }

    test_config_path = Path(__file__).parent / "test_config.json"
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message") as mock_publish,
        patch("GDPatrol.lambda_function.blacklist_ip", return_value=True),
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()
        lambda_handler(event, None)  # must not raise
        mock_publish.assert_called_once()


def test_lambda_handler_string_severity_does_not_crash_notify(monkeypatch):
    """A numeric-string severity must not crash the notify gate after actions have run."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    event = {
        "id": "test-id",
        "type": "Discovery:RDS/MaliciousIPCaller",
        "severity": "9",  # arrives as a string, not a number
        "accountId": "123456789012",
        "region": "us-east-1",
        "resource": {
            "resourceType": "RDSDBInstance",
            "rdsDbInstanceDetails": {"dbInstanceIdentifier": "testdb", "engine": "mysql"},
        },
        "service": {
            "action": {
                "actionType": "RDS_LOGIN_ATTEMPT",
                "rdsLoginAttemptAction": {"remoteIpDetails": {"ipAddressV4": "1.2.3.4"}},
            },
            "count": 1,
            "eventFirstSeen": "x",
            "eventLastSeen": "y",
        },
        "description": "RDS finding",
    }

    test_config_path = Path(__file__).parent / "test_config.json"
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message") as mock_publish,
        patch("GDPatrol.lambda_function.blacklist_ip", return_value=True),
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()
        lambda_handler(event, None)  # must not raise (severity "9" would fail "9" > 5)
        mock_publish.assert_called_once()


def test_lambda_policy_grants_ec2_actions_the_code_calls():
    """The execution policy must grant every EC2 mutating action the remediation code calls.
    Guards against a code change (e.g. the multi-ENI quarantine switching to
    modify_network_interface_attribute) that the IAM policy isn't updated to match --
    a gap moto can't catch because it doesn't enforce IAM."""
    policy = json.loads((Path(__file__).parent.parent / "lambda_policy.json").read_text())
    granted = set()
    for stmt in policy["Statement"]:
        actions = stmt["Action"]
        granted.update(actions if isinstance(actions, list) else [actions])
    required = {
        "ec2:CreateSecurityGroup",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:ModifyNetworkInterfaceAttribute",
        "ec2:CreateSnapshot",
        "ec2:CreateNetworkAclEntry",
        "ec2:DeleteNetworkAclEntry",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkAcls",
    }
    assert not (required - granted), f"lambda_policy.json missing required actions: {required - granted}"


def test_lambda_handler_survives_config_load_error():
    """A missing or malformed config.json must be logged, not crash the invocation."""
    event = {
        "id": "test-id",
        "type": "SomeType",
        "severity": 8,
        "service": {"action": {}, "count": 1, "eventFirstSeen": "x", "eventLastSeen": "y"},
    }
    with patch("builtins.open", side_effect=FileNotFoundError("config.json missing")):
        lambda_handler(event, None)  # must not raise


# --- resolve_domain_a_records tests ---


def test_resolve_domain_a_records_returns_all_unique_ips():
    """All resolved A records must be returned, not just the first."""
    fake_results = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0)),
        (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("1.2.3.4", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("5.6.7.8", 0)),
    ]
    with patch("GDPatrol.lambda_function.socket.getaddrinfo", return_value=fake_results) as mock_getaddrinfo:
        ips = resolve_domain_a_records("malicious.example.com")

    assert set(ips) == {"1.2.3.4", "5.6.7.8"}
    mock_getaddrinfo.assert_called_once()


def test_resolve_domain_a_records_sets_and_restores_timeout():
    """A bounded timeout must be applied around resolution, then restored, so a hostile
    nameserver can't hang the invocation or leak the timeout to unrelated code."""
    original = socket.getdefaulttimeout()
    with patch("GDPatrol.lambda_function.socket.getaddrinfo", return_value=[]):
        resolve_domain_a_records("example.com", timeout=3)
    assert socket.getdefaulttimeout() == original


def test_resolve_domain_a_records_handles_resolution_errors():
    """DNS failures, including a timeout, must be swallowed, returning no addresses rather than raising."""
    with patch("GDPatrol.lambda_function.socket.getaddrinfo", side_effect=socket.gaierror("no such host")):
        assert resolve_domain_a_records("nonexistent.example.com") == []

    with patch("GDPatrol.lambda_function.socket.getaddrinfo", side_effect=socket.timeout("timed out")):
        assert resolve_domain_a_records("slow.example.com") == []


def test_lambda_handler_blacklist_domain_blocks_all_resolved_ips(sample_guardduty_event, monkeypatch):
    """blacklist_domain must resolve and attempt to block every A record, not just the first."""
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/test")

    test_config_path = Path(__file__).parent / "test_config.json"
    with (
        patch("builtins.open", MagicMock()) as mock_open,
        patch("GDPatrol.lambda_function.publish_message"),
        patch("GDPatrol.lambda_function.resolve_domain_a_records", return_value=["1.2.3.4", "5.6.7.8"]),
        patch("GDPatrol.lambda_function.blacklist_ip", return_value=True) as mock_blacklist,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = test_config_path.read_text()
        lambda_handler(sample_guardduty_event, None)

        assert mock_blacklist.call_count == 2
        mock_blacklist.assert_any_call("1.2.3.4")
        mock_blacklist.assert_any_call("5.6.7.8")
