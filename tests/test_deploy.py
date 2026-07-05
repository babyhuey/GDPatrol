from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import deploy

REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]


class ResourceConflictException(Exception):
    pass


class InvalidParameterValueException(Exception):
    pass


class ResourceInUseException(Exception):
    pass


def _make_boto3_client_factory():
    """boto3.client stand-in that returns a stable MagicMock per (service, region)
    pair, so a test can configure/assert against a specific region's client."""
    clients = {}

    def fake_client(service_name, region_name=None, **kwargs):
        key = (service_name, region_name)
        if key not in clients:
            clients[key] = MagicMock(name="{}:{}".format(service_name, region_name))
        return clients[key]

    return fake_client, clients


def _seed_clients(fake_client, regions):
    """Configure happy-path responses for every AWS client deploy.run() touches."""
    ec2 = fake_client("ec2")
    ec2.describe_regions.return_value = {"Regions": [{"RegionName": r} for r in regions]}

    iam = fake_client("iam")
    iam.get_paginator.return_value.paginate.return_value = [{"Roles": []}]
    iam.create_role.return_value = {"Role": {"Arn": "arn:aws:iam::123456789012:role/GDPatrolRole"}}

    for region in regions:
        lmb = fake_client("lambda", region_name=region)
        lmb.exceptions = SimpleNamespace(
            ResourceConflictException=ResourceConflictException,
            InvalidParameterValueException=InvalidParameterValueException,
        )
        function_arn = "arn:aws:lambda:{}:123456789012:function:GDPatrol".format(region)
        lmb.create_function.return_value = {"FunctionArn": function_arn, "FunctionName": "GDPatrol"}
        lmb.update_function_code.return_value = {"FunctionArn": function_arn, "FunctionName": "GDPatrol"}

        events = fake_client("events", region_name=region)
        events.put_rule.return_value = {"RuleArn": "arn:aws:events:{}:123456789012:rule/GDPatrol".format(region)}

        gd = fake_client("guardduty", region_name=region)
        gd.list_detectors.return_value = {"DetectorIds": ["detector-1"]}
        gd.get_detector.return_value = {"Status": "ENABLED"}

        ddb = fake_client("dynamodb", region_name=region)
        ddb.exceptions = SimpleNamespace(ResourceInUseException=ResourceInUseException)


@pytest.fixture
def deploy_harness(monkeypatch, tmp_path):
    """Mocked run() harness: boto3.client returns per-region MagicMocks, the zip
    build is skipped, and sleep() is a no-op so tests run instantly."""
    fake_client, clients = _make_boto3_client_factory()
    monkeypatch.setattr(deploy.boto3, "client", fake_client)
    monkeypatch.setattr(deploy, "sleep", lambda seconds: None)

    zip_path = tmp_path / "GDPatrol.zip"
    zip_path.write_bytes(b"PK\x03\x04fake-zip-contents")
    monkeypatch.setattr(deploy, "build_function_zip", lambda: str(zip_path))

    regions = list(REGIONS)
    _seed_clients(fake_client, regions)

    return SimpleNamespace(clients=clients, regions=regions)


def test_region_failure_does_not_abort_remaining_regions(deploy_harness):
    """Regression test for the isolation fix: one region's deploy raising must
    not abort the rest of the rollout — this reproduces the two real outages
    (a member-account detector error, a mid-run file deletion)."""
    failing_region = deploy_harness.regions[1]
    failing_lmb = deploy_harness.clients[("lambda", failing_region)]
    failing_lmb.create_function.side_effect = RuntimeError("boom")
    failing_lmb.update_function_code.side_effect = RuntimeError("boom")

    deploy.run(slack_web_hook_url="https://hooks.slack.com/services/test")

    for region in deploy_harness.regions:
        if region == failing_region:
            continue
        lmb = deploy_harness.clients[("lambda", region)]
        assert lmb.create_function.called


def test_region_failure_is_reported_and_others_still_reported_successful(deploy_harness, capsys):
    failing_region = deploy_harness.regions[1]
    failing_lmb = deploy_harness.clients[("lambda", failing_region)]
    failing_lmb.create_function.side_effect = RuntimeError("boom")
    failing_lmb.update_function_code.side_effect = RuntimeError("boom")

    deploy.run(slack_web_hook_url="https://hooks.slack.com/services/test")

    out = capsys.readouterr().out
    assert "Failed to deploy region {}: boom".format(failing_region) in out
    for region in deploy_harness.regions:
        if region != failing_region:
            assert "Successfully deployed the GDPatrol lambda function in region {}".format(region) in out
    assert failing_region not in out.split("Deploy summary:")[1].split("Failed:")[0]


def test_guardduty_member_account_error_does_not_abort_region(deploy_harness):
    """update_detector raising for a member/delegated-admin account (existing
    try/except around detector management) must not block the region's deploy."""
    region = deploy_harness.regions[0]
    gd = deploy_harness.clients[("guardduty", region)]
    gd.get_detector.return_value = {"Status": "DISABLED"}
    gd.update_detector.side_effect = Exception("BadRequestException: member account")

    deploy.run(slack_web_hook_url="https://hooks.slack.com/services/test")

    lmb = deploy_harness.clients[("lambda", region)]
    assert lmb.create_function.called


def test_slack_webhook_env_var_included_when_set(deploy_harness, monkeypatch):
    monkeypatch.setenv("SLACK_WEB_HOOK_URL", "https://hooks.slack.com/services/from-env")

    deploy.run()

    for region in deploy_harness.regions:
        lmb = deploy_harness.clients[("lambda", region)]
        env_vars = lmb.create_function.call_args.kwargs["Environment"]["Variables"]
        assert env_vars["SLACK_WEB_HOOK_URL"] == "https://hooks.slack.com/services/from-env"


def test_slack_webhook_env_var_absent_when_unset(deploy_harness, monkeypatch, capsys):
    monkeypatch.delenv("SLACK_WEB_HOOK_URL", raising=False)

    deploy.run()

    for region in deploy_harness.regions:
        lmb = deploy_harness.clients[("lambda", region)]
        env_vars = lmb.create_function.call_args.kwargs["Environment"]["Variables"]
        assert "SLACK_WEB_HOOK_URL" not in env_vars
    assert "WARNING: SLACK_WEB_HOOK_URL is not set" in capsys.readouterr().out


def test_create_conflict_falls_back_to_update(deploy_harness):
    region = deploy_harness.regions[0]
    lmb = deploy_harness.clients[("lambda", region)]
    lmb.create_function.side_effect = ResourceConflictException("already exists")

    deploy.run(slack_web_hook_url="https://hooks.slack.com/services/test")

    assert lmb.update_function_code.called
    assert lmb.update_function_configuration.called
