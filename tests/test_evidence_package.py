"""Tests du module de génération du dossier de preuves."""

import json
import zipfile
from pathlib import Path

import pytest

from nis2_analyzer.core.models import load_framework, MaturityLevel
from nis2_analyzer.core.scoring import ScoringEngine
from nis2_analyzer.core.governance import assess_governance, GOVERNANCE_QUESTIONS
from nis2_analyzer.core.entity_qualification import qualify_entity, EntityProfile
from nis2_analyzer.reporting.evidence_package import (
    build_evidence_package,
    list_package_contents,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def domains_and_assessment():
    domains = load_framework()
    for domain in domains:
        for req in domain.sub_requirements:
            req.maturity = MaturityLevel(2)
    engine = ScoringEngine()
    analysis = engine.full_analysis(domains, "Acme Corp")
    return domains, analysis


@pytest.fixture
def assessment_dict(domains_and_assessment):
    return domains_and_assessment[1]


@pytest.fixture
def domains_obj(domains_and_assessment):
    return domains_and_assessment[0]


@pytest.fixture
def governance_dict():
    responses = {q.id: 2 for q in GOVERNANCE_QUESTIONS}
    return assess_governance(responses, entity_category="essentielle").to_dict()


@pytest.fixture
def qualification_dict():
    profile = EntityProfile(
        sector="sante", employees=400, annual_revenue_eur=80_000_000
    )
    return qualify_entity(profile).to_dict()


@pytest.fixture
def package_path(tmp_path, assessment_dict, domains_obj):
    out = str(tmp_path / "evidence_package.zip")
    build_evidence_package(assessment_dict, out, domains_obj=domains_obj)
    return out


# ── Structure du ZIP ─────────────────────────────────────────────────────────

class TestZipStructure:
    REQUIRED_FILES = {
        "manifest.json",
        "assessment.json",
        "gaps_action_plan.csv",
        "evidence_summary.html",
    }

    def test_zip_created(self, package_path):
        assert Path(package_path).exists()

    def test_required_files_present(self, package_path):
        with zipfile.ZipFile(package_path) as zf:
            names = set(zf.namelist())
        assert self.REQUIRED_FILES.issubset(names)

    def test_no_governance_without_input(self, package_path):
        with zipfile.ZipFile(package_path) as zf:
            assert "governance.json" not in zf.namelist()

    def test_governance_included_when_provided(self, tmp_path, assessment_dict, governance_dict):
        out = str(tmp_path / "with_gov.zip")
        build_evidence_package(assessment_dict, out, governance=governance_dict)
        with zipfile.ZipFile(out) as zf:
            assert "governance.json" in zf.namelist()

    def test_qualification_included_when_provided(self, tmp_path, assessment_dict, qualification_dict):
        out = str(tmp_path / "with_qual.zip")
        build_evidence_package(assessment_dict, out, qualification=qualification_dict)
        with zipfile.ZipFile(out) as zf:
            assert "qualification.json" in zf.namelist()


# ── manifest.json ─────────────────────────────────────────────────────────────

class TestManifest:
    def test_manifest_valid_json(self, package_path):
        with zipfile.ZipFile(package_path) as zf:
            manifest = json.loads(zf.read("manifest.json"))
        assert "generated_at" in manifest
        assert "organization" in manifest
        assert "files" in manifest

    def test_manifest_checksums_match(self, package_path):
        import hashlib
        with zipfile.ZipFile(package_path) as zf:
            manifest = json.loads(zf.read("manifest.json"))
            for filename, meta in manifest["files"].items():
                content = zf.read(filename)
                assert hashlib.sha256(content).hexdigest() == meta["sha256"]

    def test_manifest_includes_scores(self, package_path):
        with zipfile.ZipFile(package_path) as zf:
            manifest = json.loads(zf.read("manifest.json"))
        assert "scores" in manifest
        assert manifest["scores"]["overall_score"] is not None

    def test_manifest_flags_governance_absent(self, package_path):
        with zipfile.ZipFile(package_path) as zf:
            manifest = json.loads(zf.read("manifest.json"))
        assert manifest["includes_governance"] is False
        assert manifest["includes_qualification"] is False

    def test_manifest_flags_governance_present(self, tmp_path, assessment_dict, governance_dict):
        out = str(tmp_path / "full.zip")
        build_evidence_package(assessment_dict, out, governance=governance_dict)
        with zipfile.ZipFile(out) as zf:
            manifest = json.loads(zf.read("manifest.json"))
        assert manifest["includes_governance"] is True


# ── gaps_action_plan.csv ──────────────────────────────────────────────────────

class TestGapsCsv:
    def test_csv_has_header(self, package_path):
        with zipfile.ZipFile(package_path) as zf:
            content = zf.read("gaps_action_plan.csv").decode("utf-8-sig")
        assert "ID" in content
        assert "Domaine" in content
        assert "Maturité actuelle" in content

    def test_csv_has_data_rows(self, package_path):
        with zipfile.ZipFile(package_path) as zf:
            content = zf.read("gaps_action_plan.csv").decode("utf-8-sig")
        lines = [l for l in content.splitlines() if l.strip()]
        assert len(lines) > 1  # au moins header + 1 ligne de données


# ── evidence_summary.html ────────────────────────────────────────────────────

class TestEvidenceHtml:
    def test_html_contains_org_name(self, tmp_path, assessment_dict):
        out = str(tmp_path / "pkg.zip")
        build_evidence_package(assessment_dict, out, org_name="TestOrg NIS2")
        with zipfile.ZipFile(out) as zf:
            content = zf.read("evidence_summary.html").decode("utf-8")
        assert "TestOrg NIS2" in content

    def test_html_contains_score(self, package_path):
        with zipfile.ZipFile(package_path) as zf:
            content = zf.read("evidence_summary.html").decode("utf-8")
        assert "%" in content

    def test_html_xss_protection(self, tmp_path, assessment_dict):
        out = str(tmp_path / "xss.zip")
        build_evidence_package(assessment_dict, out, org_name='<script>alert("xss")</script>')
        with zipfile.ZipFile(out) as zf:
            content = zf.read("evidence_summary.html").decode("utf-8")
        assert "<script>alert" not in content

    def test_html_includes_governance_section(self, tmp_path, assessment_dict, governance_dict):
        out = str(tmp_path / "gov.zip")
        build_evidence_package(assessment_dict, out, governance=governance_dict)
        with zipfile.ZipFile(out) as zf:
            content = zf.read("evidence_summary.html").decode("utf-8")
        assert "Gouvernance" in content
        assert "Article 20" in content

    def test_html_includes_qualification_section(self, tmp_path, assessment_dict, qualification_dict):
        out = str(tmp_path / "qual.zip")
        build_evidence_package(assessment_dict, out, qualification=qualification_dict)
        with zipfile.ZipFile(out) as zf:
            content = zf.read("evidence_summary.html").decode("utf-8")
        assert "Qualification NIS 2" in content
        assert "Article 3" in content


# ── list_package_contents ────────────────────────────────────────────────────

class TestListContents:
    def test_returns_list_of_dicts(self, package_path):
        contents = list_package_contents(package_path)
        assert isinstance(contents, list)
        assert all("filename" in f and "sha256" in f for f in contents)

    def test_checksums_consistent(self, package_path):
        """Deux appels doivent donner les mêmes checksums."""
        a = {f["filename"]: f["sha256"] for f in list_package_contents(package_path)}
        b = {f["filename"]: f["sha256"] for f in list_package_contents(package_path)}
        assert a == b


# ── org_name fallback ─────────────────────────────────────────────────────────

class TestOrgNameFallback:
    def test_org_name_from_assessment_metadata(self, tmp_path, assessment_dict):
        out = str(tmp_path / "auto_name.zip")
        build_evidence_package(assessment_dict, out)  # pas de org_name explicite
        with zipfile.ZipFile(out) as zf:
            manifest = json.loads(zf.read("manifest.json"))
        assert manifest["organization"] == "Acme Corp"

    def test_explicit_org_name_overrides(self, tmp_path, assessment_dict):
        out = str(tmp_path / "override.zip")
        build_evidence_package(assessment_dict, out, org_name="Override Corp")
        with zipfile.ZipFile(out) as zf:
            manifest = json.loads(zf.read("manifest.json"))
        assert manifest["organization"] == "Override Corp"
