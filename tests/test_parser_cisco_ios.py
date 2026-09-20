"""Test: Cisco IOS parser + provenance.

Gate for P2: verifies the Cisco IOS adapter extracts CanonicalFacts
with all 6 provenance fields, that Device.serials and .hardware are lists.
"""

from __future__ import annotations

import pytest

from backend.ingest.cisco_ios import CiscoIOSAdapter

SAMPLE_IOS_CONFIG = """!
version 15.0
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
no service pad
!
hostname core-sw-01
!
boot-start-marker
boot-end-marker
!
enable secret 5 $1$abcd$xyz
!
aaa new-model
aaa authentication login default local
aaa authorization exec default local
!
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
no ip http server
ip http secure-server
!
snmp-server community public RO
snmp-server host 10.0.0.1
snmp-server enable traps
!
logging host 10.0.0.2
logging buffered 16384 informational
logging trap debugging
!
ntp server 10.0.0.3
ntp authenticate
!
banner login ^
WARNING: Unauthorized access prohibited.
^
!
interface Vlan1
 ip address 10.0.0.10 255.255.255.0
 no shutdown
!
interface Vlan2
 shutdown
!
line con 0
 exec-timeout 5 0
 login authentication default
 transport input none
!
line vty 0 4
 exec-timeout 10 0
 login authentication default
 transport input ssh
 access-class 10 in
!
ip access-list extended MGMT-ACL
 10 permit ip 10.0.0.0 0.0.0.7 any
!
end
"""


@pytest.fixture
def adapter() -> CiscoIOSAdapter:
    return CiscoIOSAdapter()


class TestCiscoIOSDetection:
    def test_can_parse_ios_config(self, adapter: CiscoIOSAdapter) -> None:
        assert adapter.can_parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")

    def test_rejects_non_ios(self, adapter: CiscoIOSAdapter) -> None:
        assert not adapter.can_parse("set firewall-policy trust-untrust", "fw.conf")


class TestCiscoIOSParsing:
    def test_parse_returns_device(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        assert result.device.hostname == "core-sw-01"
        assert result.device.device_id == "core-sw-01"
        assert isinstance(result.device.serials, list)
        assert isinstance(result.device.hardware, list)

    def test_facts_have_all_provenance_fields(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        for fact in result.facts:
            assert fact.source_file == "core-sw-01.conf"
            assert fact.line_start > 0
            assert fact.line_end >= fact.line_start
            assert fact.raw_text != ""
            assert fact.parser_id != ""
            assert fact.confidence == 1.0

    def test_ssh_version_parsed(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        ssh_facts = [f for f in result.facts if f.path == "mgmt.ssh.version"]
        assert len(ssh_facts) == 1
        assert ssh_facts[0].value == 2

    def test_enable_secret_parsed(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        secret_facts = [f for f in result.facts if f.path == "mgmt.enable_secret.hash_type"]
        assert len(secret_facts) == 1
        assert secret_facts[0].value == 5

    def test_snmp_community_parsed(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        snmp_facts = [f for f in result.facts if f.path == "snmp.community"]
        assert len(snmp_facts) == 1
        assert snmp_facts[0].value == "public"

    def test_aaa_new_model_parsed(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        aaa_facts = [f for f in result.facts if f.path == "aaa.new_model"]
        assert len(aaa_facts) == 1
        assert aaa_facts[0].value is True

    def test_vty_transport_input_parsed(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        vty_facts = [f for f in result.facts if f.path == "line.vty.transport_input"]
        assert len(vty_facts) == 1
        assert vty_facts[0].value == "ssh"

    def test_logging_remote_syslog_parsed(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        log_facts = [f for f in result.facts if f.path == "logging.remote_syslog"]
        assert len(log_facts) >= 1

    def test_login_banner_parsed(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        banner_facts = [f for f in result.facts if f.path == "mgmt.login_banner"]
        assert len(banner_facts) == 1
        assert banner_facts[0].value is True

    def test_config_hash_computed(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        assert result.device.config_hash.startswith("sha256:")

    def test_interface_state_parsed(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        iface_facts = [f for f in result.facts if f.path == "interface.admin_state"]
        assert len(iface_facts) >= 1

    def test_ntp_server_parsed(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        ntp_facts = [f for f in result.facts if f.path == "time.ntp.server"]
        assert len(ntp_facts) == 1

    def test_service_settings_parsed(self, adapter: CiscoIOSAdapter) -> None:
        result = adapter.parse(SAMPLE_IOS_CONFIG, "core-sw-01.conf")
        svc_facts = [f for f in result.facts if f.path == "service.password_encryption"]
        assert len(svc_facts) == 1
