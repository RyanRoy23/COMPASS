"""Tests du générateur de rapport HTML."""

import os
import pytest
from nis2_analyzer.core.models import load_framework, MaturityLevel
from nis2_analyzer.reporting.html_report import generate_report, _h


# ── Tests de la fonction d'échappement XSS ───────────────────────────────────

class TestHtmlEscape:
    def test_escapes_script_tag(self):
        assert "<script>" not in _h("<script>alert('xss')</script>")
        assert "&lt;script&gt;" in _h("<script>alert('xss')</script>")

    def test_escapes_double_quotes(self):
        assert '"' not in _h('"quoted"')
        assert "&quot;" in _h('"quoted"')

    def test_escapes_ampersand(self):
        assert "&amp;" in _h("A & B")

    def test_safe_string_unchanged(self):
        assert _h("TT Corporation") == "TT Corporation"

    def test_non_string_coerced(self):
        assert _h(42) == "42"


# ── Tests de génération du rapport ───────────────────────────────────────────

@pytest.fixture
def assessed_domains():
    domains = load_framework()
    answers = {
        "NIS2-D01-R01": 2, "NIS2-D01-R02": 2, "NIS2-D01-R03": 1,
        "NIS2-D01-R04": 2, "NIS2-D01-R05": 1, "NIS2-D02-R01": 2,
        "NIS2-D02-R02": 1, "NIS2-D02-R03": 0, "NIS2-D02-R04": 1,
        "NIS2-D03-R01": 1, "NIS2-D03-R02": 2, "NIS2-D03-R03": 0,
        "NIS2-D03-R04": 0, "NIS2-D04-R01": 0, "NIS2-D04-R02": 1,
        "NIS2-D04-R03": 0, "NIS2-D05-R01": 1, "NIS2-D05-R02": 2,
        "NIS2-D05-R03": 2, "NIS2-D06-R01": 1, "NIS2-D06-R02": 0,
        "NIS2-D07-R01": 2, "NIS2-D07-R02": 1, "NIS2-D07-R03": 2,
        "NIS2-D07-R04": 0, "NIS2-D07-R05": 1, "NIS2-D08-R01": 2,
        "NIS2-D08-R02": 2, "NIS2-D09-R01": 2, "NIS2-D09-R02": 2,
        "NIS2-D09-R03": 1, "NIS2-D09-R04": 1, "NIS2-D10-R01": 3,
        "NIS2-D10-R02": 2, "NIS2-D10-R03": 1,
    }
    for domain in domains:
        for req in domain.sub_requirements:
            if req.id in answers:
                req.maturity = MaturityLevel(answers[req.id])
    return domains


class TestGenerateReport:
    def test_creates_file(self, assessed_domains, tmp_path):
        out = str(tmp_path / "report.html")
        result = generate_report(assessed_domains, "TT Corporation", output_path=out)
        assert os.path.exists(out)
        assert result == out

    def test_output_is_valid_html(self, assessed_domains, tmp_path):
        out = str(tmp_path / "report.html")
        generate_report(assessed_domains, "TT Corporation", output_path=out)
        content = open(out, encoding="utf-8").read()
        assert "<!DOCTYPE html>" in content
        assert "</html>" in content

    def test_org_name_appears_in_report(self, assessed_domains, tmp_path):
        out = str(tmp_path / "report.html")
        generate_report(assessed_domains, "TT Corporation", output_path=out)
        content = open(out, encoding="utf-8").read()
        assert "TT Corporation" in content

    def test_xss_org_name_is_escaped(self, assessed_domains, tmp_path):
        out = str(tmp_path / "report.html")
        malicious = '<script>alert("xss")</script>'
        generate_report(assessed_domains, malicious, output_path=out)
        content = open(out, encoding="utf-8").read()
        assert "<script>alert" not in content
        assert "&lt;script&gt;" in content

    def test_report_contains_grade(self, assessed_domains, tmp_path):
        out = str(tmp_path / "report.html")
        generate_report(assessed_domains, "TT Corporation", output_path=out)
        content = open(out, encoding="utf-8").read()
        # Le grade doit être A, B, C, D, E ou F
        assert any(f"Grade {g}" in content for g in "ABCDEF")

    def test_creates_parent_directory(self, assessed_domains, tmp_path):
        out = str(tmp_path / "subdir" / "report.html")
        generate_report(assessed_domains, "TT Corporation", output_path=out)
        assert os.path.exists(out)

    def test_report_contains_nis2_reference(self, assessed_domains, tmp_path):
        out = str(tmp_path / "report.html")
        generate_report(assessed_domains, "TT Corporation", output_path=out)
        content = open(out, encoding="utf-8").read()
        assert "NIS 2" in content or "NIS2" in content

    def test_report_with_no_answers(self, tmp_path):
        domains = load_framework()
        out = str(tmp_path / "empty_report.html")
        generate_report(domains, "Org vide", output_path=out)
        assert os.path.exists(out)
