"""Tests for the IoC Extraction Engine."""

import pytest
from minos.extractor import extract_iocs, extract_iocs_from_file
from minos.models import IoC, IoCType


class TestIPv4Extraction:
    def test_single_ipv4(self):
        iocs = extract_iocs("Connection from 192.168.1.1 established.")
        assert len(iocs) == 1
        assert iocs[0].ioc_type == IoCType.IPV4
        assert iocs[0].value == "192.168.1.1"

    def test_multiple_ipv4(self):
        iocs = extract_iocs("Src: 10.0.0.1, Dst: 172.16.5.254")
        assert len(iocs) == 2
        assert {ioc.value for ioc in iocs} == {"10.0.0.1", "172.16.5.254"}

    def test_invalid_ipv4_rejected(self):
        # 999 is not a valid octet
        iocs = extract_iocs("Bad IP: 999.999.999.999")
        assert len([i for i in iocs if i.ioc_type == IoCType.IPV4]) == 0

    def test_deduplicate_ipv4(self):
        iocs = extract_iocs("1.1.1.1 and 1.1.1.1 again", deduplicate=True)
        assert len([i for i in iocs if i.value == "1.1.1.1"]) == 1

    def test_full_public_ip_range(self):
        for ip in ("8.8.8.8", "203.0.113.42", "255.255.255.255"):
            iocs = extract_iocs(f"IP: {ip}")
            assert any(i.value == ip for i in iocs), f"{ip} should be extracted"


class TestDomainExtraction:
    def test_simple_domain(self):
        iocs = extract_iocs("Visit example.com for details.")
        domains = [i for i in iocs if i.ioc_type == IoCType.DOMAIN]
        assert any(i.value == "example.com" for i in domains)

    def test_subdomain(self):
        iocs = extract_iocs("C2 at api.malicious.evil.com detected.")
        domains = [i for i in iocs if i.ioc_type == IoCType.DOMAIN]
        assert any(i.value == "api.malicious.evil.com" for i in domains)

    def test_domain_lowercased(self):
        iocs = extract_iocs("BadServer.Example.COM is suspect.")
        domains = [i for i in iocs if i.ioc_type == IoCType.DOMAIN]
        assert all(i.value == i.value.lower() for i in domains)

    def test_ipv4_not_mistaken_for_domain(self):
        iocs = extract_iocs("Addr: 192.168.1.1")
        domains = [i for i in iocs if i.ioc_type == IoCType.DOMAIN]
        assert len(domains) == 0

    def test_executable_extensions_rejected(self):
        """Windows .exe/.dll/.sys should NOT be extracted as domains."""
        iocs = extract_iocs("Process: svchost.exe, driver: kernel32.dll")
        domains = [i for i in iocs if i.ioc_type == IoCType.DOMAIN]
        assert all("svchost.exe" not in i.value for i in domains)
        assert all("kernel32.dll" not in i.value for i in domains)

    def test_real_domain_not_rejected(self):
        """A real .com/.net/.org domain should still pass."""
        iocs = extract_iocs("C2 at evil.com and bad.net")
        domains = [i for i in iocs if i.ioc_type == IoCType.DOMAIN]
        values = {i.value for i in domains}
        assert "evil.com" in values
        assert "bad.net" in values


class TestHashExtraction:
    def test_md5(self):
        iocs = extract_iocs("File hash: d41d8cd98f00b204e9800998ecf8427e")
        md5s = [i for i in iocs if i.ioc_type == IoCType.MD5]
        assert len(md5s) == 1
        assert md5s[0].value == "d41d8cd98f00b204e9800998ecf8427e"

    def test_sha256(self):
        iocs = extract_iocs(
            "SHA256=a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        )
        sha256s = [i for i in iocs if i.ioc_type == IoCType.SHA256]
        assert len(sha256s) == 1

    def test_no_duplicate_hash_types(self):
        """If a SHA256 appears, its first 32 chars should NOT be extracted as MD5."""
        sha = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        iocs = extract_iocs(f"hash: {sha}")
        md5s = [i for i in iocs if i.ioc_type == IoCType.MD5 and i.value == sha[:32]]
        assert len(md5s) == 0

    def test_mixed_hashes(self):
        text = (
            "md5=d41d8cd98f00b204e9800998ecf8427e "
            "sha256=a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        )
        iocs = extract_iocs(text)
        type_counts = {}
        for i in iocs:
            type_counts[i.ioc_type] = type_counts.get(i.ioc_type, 0) + 1
        assert type_counts.get(IoCType.MD5, 0) == 1
        assert type_counts.get(IoCType.SHA256, 0) == 1


class TestSysmonLog:
    def test_extract_from_file(self):
        iocs = extract_iocs_from_file("sample_logs/sysmon_1.txt")
        # Expected: 192.168.1.45, 203.0.113.42, malicious-c2.evil.com,
        #           md5=8a5b..., sha256=e3b0...
        assert len(iocs) >= 4
        values = {i.value for i in iocs}
        assert "192.168.1.45" in values
        assert "203.0.113.42" in values
        assert "malicious-c2.evil.com" in values


class TestEmptyInput:
    def test_empty_string(self):
        assert extract_iocs("") == []

    def test_no_iocs(self):
        iocs = extract_iocs("Plain text with no indicators at all.")
        assert iocs == []
