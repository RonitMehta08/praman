"""Remediation playbook module.

Provides remediation guidance for findings. Each remediation_ref points to
a playbook entry with vendor-specific fix commands and explanations.

This module sits AFTER the verdict — it provides recommended actions
for findings that already have a result set by the rules engine.
"""

from __future__ import annotations

from typing import Any

# Remediation playbook — indexed by remediation_ref
# The key matches Finding.remediation_ref
PLAYBOOK: dict[str, dict[str, Any]] = {
    "stig-ndm-v215844-remediation": {
        "title": "Enable SSH version 2",
        "description": "Configure SSH version 2 to ensure encrypted management sessions.",
        "commands": {
            "cisco_ios": [
                "ip ssh version 2",
                "ip ssh time-out 60",
                "ip ssh authentication-retries 3",
            ],
            "juniper_junos": [
                "set system services ssh protocol-version v2",
            ],
        },
        "verification": "show ip ssh | include SSH",
        "rollback": "no ip ssh version 2",
        "risk_of_fix": "low",
    },
    "stig-ndm-v215845-remediation": {
        "title": "Restrict VTY transport to SSH only",
        "description": "Configure VTY lines to accept only SSH connections.",
        "commands": {
            "cisco_ios": [
                "line vty 0 15",
                " transport input ssh",
            ],
        },
        "verification": "show running-config | section line vty",
        "rollback": "line vty 0 15\n transport input all",
        "risk_of_fix": "medium",
    },
    "stig-ndm-v220140-remediation": {
        "title": "Enable AAA new-model",
        "description": "Enable AAA for centralized authentication, authorization, and accounting.",
        "commands": {
            "cisco_ios": [
                "aaa new-model",
                "aaa authentication login default local",
                "aaa authorization exec default local",
            ],
        },
        "verification": "show aaa | include method",
        "rollback": "no aaa new-model",
        "risk_of_fix": "high",
    },
    "stig-ndm-v215814-remediation": {
        "title": "Configure login banner",
        "description": "Set a warning banner displayed before login.",
        "commands": {
            "cisco_ios": [
                'banner login ^',
                'WARNING: Unauthorized access to this system is prohibited.',
                'All activity is monitored and logged.',
                '^',
            ],
        },
        "verification": "show running-config | section banner",
        "rollback": "no banner login",
        "risk_of_fix": "low",
    },
    "stig-ndm-v215823-remediation": {
        "title": "Replace SNMP v1/v2 with v3",
        "description": "Remove SNMP community strings and configure SNMPv3 with auth+priv.",
        "commands": {
            "cisco_ios": [
                "no snmp-server community public RO",
                "no snmp-server community private RW",
                "snmp-server group SNMPv3Group v3 priv",
                "snmp-server user SNMPv3User SNMPv3Group v3 auth sha <auth-pass> priv aes 256 <priv-pass>",
            ],
        },
        "verification": "show snmp group\nshow snmp user",
        "rollback": "snmp-server community public RO",
        "risk_of_fix": "medium",
    },
}


def get_remediation(remediation_ref: str | None) -> dict[str, Any] | None:
    """Look up remediation guidance by its reference ID."""
    if remediation_ref is None:
        return None
    return PLAYBOOK.get(remediation_ref)


def get_commands_for_vendor(
    remediation_ref: str | None,
    vendor: str,
) -> list[str]:
    """Get vendor-specific remediation commands."""
    playbook = get_remediation(remediation_ref)
    if playbook is None:
        return []
    commands = playbook.get("commands", {})
    return commands.get(vendor, commands.get("cisco_ios", []))
