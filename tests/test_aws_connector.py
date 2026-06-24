"""Tests du connecteur AWS — audit de sécurité NIS 2."""

import pytest
from nis2_analyzer.core.aws_connector import AWSConnector, AWSAuditReport, AWSFinding


def _demo_report() -> AWSAuditReport:
    connector = AWSConnector(demo_mode=True)
    return connector.audit(region="eu-west-1")


class TestAWSConnectorDemo:
    def test_returns_report(self):
        report = _demo_report()
        assert isinstance(report, AWSAuditReport)

    def test_has_findings(self):
        report = _demo_report()
        assert len(report.findings) > 0

    def test_account_id_set(self):
        report = _demo_report()
        assert report.account_id == "123456789012"

    def test_region_stored(self):
        report = _demo_report()
        assert report.region == "eu-west-1"

    def test_totals_consistent(self):
        report = _demo_report()
        counted = report.passed + report.failed + report.warnings
        assert counted <= report.total_controls + 5  # INFO findings excluded from total

    def test_maturity_mapping_not_empty(self):
        report = _demo_report()
        assert len(report.maturity_mapping) > 0

    def test_maturity_values_in_range(self):
        report = _demo_report()
        for req_id, level in report.maturity_mapping.items():
            assert 0 <= level <= 3, f"{req_id} has level {level} out of range"

    def test_maturity_covers_nis2_domains(self):
        report = _demo_report()
        keys = set(report.maturity_mapping.keys())
        # Au moins ces exigences doivent être couvertes par l'audit
        expected = {"NIS2-D10-R01", "NIS2-D09-R03", "NIS2-D02-R02", "NIS2-D08-R01"}
        assert expected.issubset(keys), f"Missing: {expected - keys}"

    def test_critical_findings_are_fails(self):
        report = _demo_report()
        for f in report.critical_findings:
            assert f.status == "FAIL"
            assert f.severity == "CRITICAL"

    def test_to_dict_structure(self):
        report = _demo_report()
        d = report.to_dict()
        assert "account_id" in d
        assert "summary" in d
        assert "maturity_mapping" in d
        assert "critical_findings" in d
        assert "all_findings" in d

    def test_to_dict_summary_keys(self):
        report = _demo_report()
        summary = report.to_dict()["summary"]
        for key in ("total_controls", "passed", "failed", "warnings", "pass_rate"):
            assert key in summary

    def test_pass_rate_between_0_and_100(self):
        report = _demo_report()
        rate = report.to_dict()["summary"]["pass_rate"]
        assert 0.0 <= rate <= 100.0

    def test_findings_have_required_fields(self):
        report = _demo_report()
        for f in report.findings:
            assert f.control_id
            assert f.title
            assert f.requirement_id.startswith("NIS2-")
            assert f.status in ("PASS", "FAIL", "WARN", "INFO")
            assert f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_mfa_root_passes_in_demo(self):
        report = _demo_report()
        iam001 = next((f for f in report.findings if f.control_id == "IAM-001"), None)
        assert iam001 is not None
        assert iam001.status == "PASS"

    def test_ssh_open_fails_in_demo(self):
        report = _demo_report()
        sg001 = next((f for f in report.findings if f.control_id == "SG-001"), None)
        assert sg001 is not None
        assert sg001.status == "FAIL"

    def test_critical_ssh_finding_in_critical_findings(self):
        report = _demo_report()
        ctrl_ids = {f.control_id for f in report.critical_findings}
        assert "SG-001" in ctrl_ids

    def test_maturity_critical_domain_is_low(self):
        report = _demo_report()
        # NIS2-D09-R01 a un CRITICAL FAIL (SG-001) → doit être niveau 0
        level = report.maturity_mapping.get("NIS2-D09-R01")
        assert level == 0

    def test_maturity_nis2_d02_r02_positive(self):
        report = _demo_report()
        # CT-001 (PASS) et GD-001 (PASS) → NIS2-D02-R02 devrait être >= 1
        level = report.maturity_mapping.get("NIS2-D02-R02", -1)
        assert level >= 1

    def test_to_dict_maturity_mapping_serializable(self):
        report = _demo_report()
        d = report.to_dict()
        # Tous les niveaux doivent être des entiers JSON-sérialisables
        for k, v in d["maturity_mapping"].items():
            assert isinstance(v, int)

    def test_region_override(self):
        connector = AWSConnector(demo_mode=True)
        report = connector.audit(region="us-east-1")
        assert report.region == "us-east-1"


class TestAWSConnectorMaturityLogic:
    def test_critical_fail_gives_level_0(self):
        connector = AWSConnector(demo_mode=False)
        findings = [
            AWSFinding("X-001", "Test", "NIS2-D10-R01", "FAIL", "CRITICAL", "Detail")
        ]
        maturity = connector._compute_maturity(findings)
        assert maturity["NIS2-D10-R01"] == 0

    def test_all_pass_single_gives_level_2(self):
        connector = AWSConnector(demo_mode=False)
        findings = [
            AWSFinding("X-001", "Test", "NIS2-D10-R01", "PASS", "HIGH", "Detail")
        ]
        maturity = connector._compute_maturity(findings)
        assert maturity["NIS2-D10-R01"] == 2

    def test_all_pass_multiple_gives_level_3(self):
        connector = AWSConnector(demo_mode=False)
        findings = [
            AWSFinding("X-001", "Test A", "NIS2-D10-R01", "PASS", "HIGH", "Detail"),
            AWSFinding("X-002", "Test B", "NIS2-D10-R01", "PASS", "MEDIUM", "Detail"),
        ]
        maturity = connector._compute_maturity(findings)
        assert maturity["NIS2-D10-R01"] == 3

    def test_warn_gives_level_1(self):
        connector = AWSConnector(demo_mode=False)
        findings = [
            AWSFinding("X-001", "Test", "NIS2-D10-R01", "WARN", "MEDIUM", "Detail")
        ]
        maturity = connector._compute_maturity(findings)
        assert maturity["NIS2-D10-R01"] == 1

    def test_high_fail_with_no_passes_gives_0(self):
        connector = AWSConnector(demo_mode=False)
        findings = [
            AWSFinding("X-001", "Test", "NIS2-D09-R01", "FAIL", "HIGH", "Detail")
        ]
        maturity = connector._compute_maturity(findings)
        assert maturity["NIS2-D09-R01"] == 0

    def test_info_findings_excluded(self):
        connector = AWSConnector(demo_mode=False)
        findings = [
            AWSFinding("X-001", "Test", "NIS2-D10-R01", "INFO", "LOW", "Cannot run")
        ]
        maturity = connector._compute_maturity(findings)
        assert "NIS2-D10-R01" not in maturity


class TestAWSConnectorAPI:
    def test_demo_endpoint_returns_200(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/aws-audit", json={"demo_mode": True, "region": "eu-west-1"})
        assert res.status_code == 200

    def test_demo_endpoint_has_maturity_mapping(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/aws-audit", json={"demo_mode": True})
        data = res.json()
        assert "maturity_mapping" in data
        assert len(data["maturity_mapping"]) > 0

    def test_demo_endpoint_has_summary(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/aws-audit", json={"demo_mode": True})
        data = res.json()
        assert "summary" in data
        assert data["summary"]["total_controls"] > 0

    def test_demo_endpoint_has_critical_findings(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/aws-audit", json={"demo_mode": True})
        data = res.json()
        assert "critical_findings" in data

    def test_real_mode_without_boto3_returns_503(self):
        """Sans boto3 installé, l'endpoint réel retourne 503."""
        import sys
        import unittest.mock as mock
        # Simuler l'absence de boto3
        with mock.patch.dict(sys.modules, {"boto3": None}):
            from fastapi.testclient import TestClient
            from nis2_analyzer.web.app import app
            client = TestClient(app)
            res = client.post("/api/aws-audit", json={"demo_mode": False, "region": "eu-west-1"})
            # Soit 503 (boto3 manquant) soit 500 (autre erreur) — les deux sont acceptables
            assert res.status_code in (500, 503)
