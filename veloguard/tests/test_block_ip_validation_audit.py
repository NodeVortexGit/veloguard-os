"""Audit block_ip validation and protected-range policy behavior.

These tests describe the required behavior for block_ip and unblock_ip.
"""

from copy import deepcopy

import pytest

from veloguard.guardd.actions import Action, ActionType
from veloguard.guardd.policy import DEFAULT_POLICY, PolicyEngine, Verdict


DENY_ADDRESSES = [
    "127.0.0.1",
    "::1",
    "::ffff:127.0.0.1",
    "::FFFF:127.0.0.1",
    "::ffff:10.1.2.3",
    "::ffff:192.168.1.1",
    "::ffff:172.16.0.1",
    "10.1.2.3",
    "192.168.1.1",
    "172.16.0.1",
    "172.31.255.255",
    "fd00::1",
    "fe80::1",
    "::",
    "0.0.0.0",
    "169.254.1.1",
]

ALLOW_ADDRESSES = [
    "8.8.8.8",
    "1.1.1.1",
    "9.9.9.9",
    "2606:4700:4700::1111",
    "203.0.113.5",
]

MALFORMED_ADDRESSES = [
    "not-an-ip",
    "999.999.999.999",
    "::ffff:999.1.1.1",
    "",
    "127.1",
]


def ip_action_verdict(ip: str, action_type: ActionType = ActionType.BLOCK_IP) -> Verdict:
    """Return the policy verdict after the production Action validation step.

    Approval is disabled in this test policy so the result isolates IP
    validation/protected-range policy (rather than interactive consent).
    Invalid addresses fail closed as DENY.
    """
    action = Action(action_type, {"ip": ip})
    try:
        action.validate()
    except (TypeError, ValueError):
        return Verdict.DENY

    policy = deepcopy(DEFAULT_POLICY)
    policy["require_approval"] = []
    return PolicyEngine(policy).evaluate(action).verdict


@pytest.mark.parametrize("ip", DENY_ADDRESSES)
def test_block_ip_denies_protected_addresses(ip):
    assert ip_action_verdict(ip) is Verdict.DENY


@pytest.mark.parametrize("ip", ALLOW_ADDRESSES)
def test_block_ip_allows_public_addresses(ip):
    assert ip_action_verdict(ip) is Verdict.ALLOW


@pytest.mark.parametrize("ip", MALFORMED_ADDRESSES)
def test_block_ip_malformed_input_fails_closed(ip):
    assert ip_action_verdict(ip) is Verdict.DENY


@pytest.mark.parametrize("ip", ["127.0.0.1", "::ffff:127.0.0.1"])
def test_unblock_ip_denies_protected_localhost(ip):
    assert ip_action_verdict(ip, ActionType.UNBLOCK_IP) is Verdict.DENY
