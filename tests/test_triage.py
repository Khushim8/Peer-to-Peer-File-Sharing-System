"""Unit tests for scripts/triage.py, using the small reports in tests/fixtures/triage/."""
import csv
import datetime as dt
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import triage  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "triage"
STRIP = ["/src"]


def load(name):
    return triage.load_json(FIXTURES / name)


def by(findings, **kw):
    return [f for f in findings if all(getattr(f, k) == v for k, v in kw.items())]


@pytest.fixture()
def run_dir(tmp_path):
    """A report folder with every fixture, plus an offline EPSS/KEV cache and an empty triage file."""
    reports = tmp_path / "reports"
    shutil.copytree(FIXTURES, reports, ignore=shutil.ignore_patterns("cache"))
    shutil.copytree(FIXTURES / "cache", tmp_path / "cache")
    (tmp_path / "triage.yaml").write_text("decisions: []\n")
    return tmp_path


def run_main(run_dir, *extra):
    return triage.main([str(run_dir / "reports"), "--out", str(run_dir / "out"), "--offline",
                        "--cache-dir", str(run_dir / "cache"), "--triage-file", str(run_dir / "triage.yaml"),
                        *extra])


def read_csv(run_dir):
    with open(run_dir / "out" / "findings.csv", newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# ---------------------------------------------------------------- parsers

def test_semgrep_sarif():
    fs = triage.parse_sarif(load("semgrep.sarif"), STRIP)
    assert len(fs) == 4
    docker = by(fs, line_or_version="15")[0]
    assert docker.tool == "semgrep"
    assert docker.category == "iac"
    assert docker.file_or_package == "p2p/peer_client/Dockerfile"   # Windows separators normalized
    assert docker.severity == "HIGH"                                 # SARIF level error
    path = by(fs, file_or_package="p2p/peer_client/server.py")[0]
    assert (path.category, path.severity, path.cwe) == ("sast", "MEDIUM", {22})


def test_codeql_sarif_rules_in_extensions():
    [f] = triage.parse_sarif(load("codeql.sarif"), STRIP)
    assert f.tool == "codeql"
    assert f.severity == "HIGH"              # from security-severity 7.5
    assert f.cwe == {22, 23}
    assert f.fingerprint == "abc123:1"


def test_osv_direct_vs_inferred_and_fixed_version():
    fs = triage.parse_osv(load("osv.json"), STRIP)
    assert len(fs) == 4
    web3 = by(fs, file_or_package="web3")
    assert {f.inferred for f in web3} == {False}
    assert web3[0].fixed_version == "7.15.0"
    assert web3[0].location == {"p2p/peer_client/requirements.txt"}
    assert "CVE-2099-0001" in web3[0].cves
    aio = {f.rule_or_cve: f for f in by(fs, file_or_package="aiohttp")}
    assert {f.inferred for f in aio.values()} == {True}
    # Two fixed events; 3.9.2 is below the installed 3.9.5, so 3.14.0 is the fix.
    assert aio["GHSA-dddd-eeee-ffff"].fixed_version == "3.14.0"
    assert aio["GHSA-dddd-eeee-ffff"].cvss == 9.8
    assert aio["GHSA-dddd-eeee-ffff"].severity == "CRITICAL"


def test_trivy_image_origin_fix_status_and_cvss():
    fs = triage.parse_trivy(load("trivy-image-test.json"), "trivy-image-test.json", load("base-images.json"), STRIP)
    openssl, kernel, aio = (by(fs, file_or_package=p)[0] for p in ("openssl", "linux-libc-dev", "aiohttp"))
    assert openssl.tool == "trivy-image" and openssl.category == "container"
    assert openssl.origin == {"base-os"}
    assert openssl.cvss == 9.8                # NVD preferred over vendor scores
    assert openssl.fix_status == "fixed"
    assert kernel.fix_status == "no-fix"      # Status: affected
    assert aio.origin == {"app-dep"}          # pip layer added by the Dockerfile
    assert aio.ecosystem == "pypi"


def test_trivy_image_origin_unknown_without_matching_base(capsys):
    fs = triage.parse_trivy(load("trivy-image-test.json"), "trivy-image-test.json", {}, STRIP)
    assert {o for f in fs for o in f.origin} == {"unknown"}
    assert "no verified base-image layers" in capsys.readouterr().err


def test_trivy_config_skips_passed_checks():
    fs = triage.parse_trivy(load("trivy-config.json"), "trivy-config.json", {}, STRIP)
    assert [(f.tool, f.category, f.rule_or_cve) for f in fs] == [("trivy-config", "iac", "DS-0002")]


def test_gitleaks():
    [f] = triage.parse_gitleaks(load("gitleaks.json"), STRIP)
    assert (f.category, f.rule_or_cve, f.file_or_package, f.line_or_version) == ("secret", "generic-api-key", "p2p/config.py", "4")


def test_version_key_ordering():
    ordered = ["3.9.2", "3.9.5", "3.10.0", "3.14.0b1", "3.14.0", "3.14.0.1"]
    assert sorted(reversed(ordered), key=triage.version_key) == ordered


# ---------------------------------------------------------------- dedup + metrics

def test_dedup_merges_aliases_across_tools():
    raw = triage.load_reports(FIXTURES, STRIP)
    merged = triage.deduplicate(raw)
    [aio] = [f for f in merged if f.file_or_package == "aiohttp" and "CVE-2099-0002" in f.cves]
    assert aio.reported_by == ["osv-scanner", "trivy-image"]
    assert aio.inferred is False              # confirmed by the installed package in the image
    assert aio.rule_or_cve == "CVE-2099-0002"
    assert aio.cvss == 9.8
    [web3] = by(merged, file_or_package="web3")   # same advisory in two manifests
    assert len(web3.location) == 2
    [other_aio] = [f for f in merged if "CVE-2099-0005" in f.cves]
    assert other_aio.inferred is True


def test_dedup_rule_classes_across_tools():
    merged = triage.deduplicate(triage.load_reports(FIXTURES, STRIP))
    [root_user] = [f for f in merged if f.rule_class == "dockerfile-root-user"]
    assert root_user.reported_by == ["semgrep", "trivy-config"]
    [path] = [f for f in merged if f.file_or_package == "p2p/peer_client/server.py"]
    assert sorted(path.reported_by) == ["codeql", "semgrep"]   # same CWE class, file and line


def test_tool_metrics_count_unique_pairs_not_entries():
    m = triage.tool_metrics(triage.load_reports(FIXTURES, STRIP))
    osv = m["osv-scanner"]
    assert osv["raw_entries"] == 4
    assert osv["pairs"] == 3                  # web3 advisory reported from two manifests
    assert osv["inferred"] == {"direct": 1, "inferred": 2}
    img = m["trivy-image"]
    assert img["origin"] == {"base-os": 2, "app-dep": 1}
    assert img["fix"] == {"fixed": 2, "no-fix": 1}
    assert m["semgrep"]["other"] == 3         # two missing-user hits on one file count once


def test_vendor_advisory_ids_do_not_merge_distinct_cves():
    vulns = [{"VulnerabilityID": cve, "PkgName": "linux-libc-dev", "InstalledVersion": "6.12", "Status": "fixed",
              "Severity": "HIGH", "VendorIDs": ["DSA-6238-1"], "Layer": {"DiffID": "sha256:base1"}}
             for cve in ("CVE-2099-0101", "CVE-2099-0102")]
    report = {"ArtifactName": "img:test", "ArtifactType": "container_image",
              "Metadata": {"DiffIDs": ["sha256:base1"]},
              "Results": [{"Target": "img", "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": vulns}]}
    merged = triage.deduplicate(triage.parse_trivy(report, "trivy-image.json", {}, STRIP))
    assert sorted(f.rule_or_cve for f in merged) == ["CVE-2099-0101", "CVE-2099-0102"]
    assert all(f.cves == {f.rule_or_cve} for f in merged)


def test_kev_lookup_is_exact_id_membership(tmp_path):
    (tmp_path / "kev.json").write_text('{"catalogVersion": "t", "vulnerabilities": [{"cveID": "CVE-2026-1114"}]}')
    (tmp_path / "epss.json").write_text("{}")
    long_id = triage.Finding("trivy-image", "container", "CVE-2026-111497", "HIGH", "libbrotli1")
    exact = triage.Finding("trivy-image", "container", "CVE-2026-1114", "HIGH", "libfoo")
    triage.enrich([long_id, exact], tmp_path, offline=True)
    assert long_id.kev is False
    assert exact.kev is True


# ---------------------------------------------------------------- priority + triage

def test_prioritize_rules():
    f = triage.Finding
    assert triage.prioritize(f("x", "container", "CVE-1", "LOW", "pkg", kev=True), ["p2p/"]) == "P1"
    assert triage.prioritize(f("x", "container", "CVE-1", "CRITICAL", "pkg", cvss=9.8, epss=0.1), ["p2p/"]) == "P1"
    assert triage.prioritize(f("x", "container", "CVE-1", "CRITICAL", "pkg", cvss=9.8, epss=0.09), ["p2p/"]) == "P2"
    assert triage.prioritize(f("x", "sca", "CVE-1", "MEDIUM", "pkg", cvss=6.9), ["p2p/"]) == "P3"
    assert triage.prioritize(f("x", "iac", "DS-0002", "HIGH", "Dockerfile"), ["p2p/"]) == "P2"
    sast = dict(tool="semgrep", category="sast", rule_or_cve="r", severity="MEDIUM", cwe={22})
    assert triage.prioritize(f(file_or_package="p2p/a.py", **sast), ["p2p/"]) == "P2"
    assert triage.prioritize(f(file_or_package="tools/a.py", **sast), ["p2p/"]) == "P3"
    secret = f("gitleaks", "secret", "generic-api-key", "MEDIUM", "a.py")
    assert triage.prioritize(secret, ["p2p/"]) == "P3"
    secret.triage_status = "confirmed_live"
    assert triage.prioritize(secret, ["p2p/"]) == "P1"


@pytest.mark.parametrize("decision, message", [
    ({"rule_or_cve": "CVE-1", "status": "false_positive"}, "reason"),
    ({"rule_or_cve": "CVE-*", "status": "accepted_risk", "reason": "x"}, "wildcards"),
    ({"rule_or_cve": "CVE-1", "status": "ignore", "reason": "x"}, "status"),
    ({"status": "accepted_risk", "reason": "x"}, "'id' or a 'rule_or_cve'"),
])
def test_triage_file_validation(tmp_path, decision, message):
    path = tmp_path / "triage.yaml"
    import yaml
    path.write_text(yaml.safe_dump({"decisions": [decision]}))
    with pytest.raises(ValueError, match=message):
        triage.load_triage(path)


def test_apply_triage_matches_aliases_and_honours_expiry():
    f = triage.Finding("osv-scanner", "sca", "CVE-2099-0001", "HIGH", "web3", aliases={"PYSEC-2099-1"})
    notes = triage.apply_triage([f], [
        {"rule_or_cve": "PYSEC-2099-1", "status": "accepted_risk", "reason": "not reachable", "expires": "2000-01-01"},
        {"rule_or_cve": "CVE-2099-9999", "status": "false_positive", "reason": "typo"},
    ], dt.date(2026, 11, 6))
    assert f.triage_status == "open"
    assert any(n.startswith("expired") for n in notes) and any(n.startswith("matched nothing") for n in notes)
    triage.apply_triage([f], [{"rule_or_cve": "PYSEC-2099-1", "status": "accepted_risk", "reason": "not reachable"}],
                        dt.date(2026, 11, 6))
    assert (f.triage_status, f.triage_reason) == ("accepted_risk", "not reachable")


# ---------------------------------------------------------------- end to end

def test_main_gate_fails_on_new_p1_and_writes_outputs(run_dir):
    assert run_main(run_dir) == 1
    rows = read_csv(run_dir)
    p1 = {(r["file_or_package"], r["rule_or_cve"]) for r in rows if r["priority"] == "P1"}
    assert p1 == {("openssl", "CVE-2099-0003"), ("linux-libc-dev", "CVE-2099-0004")}
    kernel = next(r for r in rows if r["file_or_package"] == "linux-libc-dev")
    assert kernel["kev"] == "True" and kernel["epss"] == "0.001"
    summary = (run_dir / "out" / "summary.md").read_text(encoding="utf-8")
    assert "2099.01.01" in summary and "## New P1 findings" in summary


def test_main_gate_passes_when_p1s_are_known(run_dir):
    assert run_main(run_dir) == 1
    (run_dir / "out" / "findings.csv").replace(run_dir / "previous.csv")
    assert run_main(run_dir, "--compare-to", str(run_dir / "previous.csv")) == 0
    assert {r["new"] for r in read_csv(run_dir)} == {"False"}


def test_main_gate_fails_when_known_finding_escalates_to_p1(run_dir):
    assert run_main(run_dir) == 1
    rows = read_csv(run_dir)
    for r in rows:
        if r["priority"] == "P1" and r["file_or_package"] == "openssl":
            r["priority"] = "P2"            # known before, but only as P2
    with open(run_dir / "previous.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    assert run_main(run_dir, "--compare-to", str(run_dir / "previous.csv")) == 1
    new = {r["file_or_package"] for r in read_csv(run_dir) if r["new"] == "True"}
    assert new == {"openssl"}


def test_main_triaged_p1_does_not_fail_gate(run_dir):
    (run_dir / "triage.yaml").write_text(
        "decisions:\n"
        "  - {rule_or_cve: CVE-2099-0003, status: accepted_risk, reason: test}\n"
        "  - {rule_or_cve: CVE-2099-0004, file_or_package: linux-libc-dev, status: false_positive, reason: headers only}\n")
    assert run_main(run_dir) == 0
    status = {r["file_or_package"]: r["triage_status"] for r in read_csv(run_dir)}
    assert status["openssl"] == "accepted_risk" and status["linux-libc-dev"] == "false_positive"


def test_main_rejects_bad_triage_file(run_dir):
    (run_dir / "triage.yaml").write_text("decisions:\n  - {rule_or_cve: CVE-1, status: false_positive}\n")
    assert run_main(run_dir) == 2


def test_main_writes_step_summary(run_dir, monkeypatch):
    step = run_dir / "step.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step))
    run_main(run_dir)
    assert "New P1: **2** (gate fails)" in step.read_text(encoding="utf-8")
