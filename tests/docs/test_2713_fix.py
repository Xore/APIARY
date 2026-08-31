#!/usr/bin/env python3
"""Regression test for #2713: hp-arkime-capture loaded zero protocol parsers
and had no GeoIP.

Two independent silent misconfigurations in honeypot-elk's Arkime services:

1. config.ini left parsersDir at its relative default ("./parsers"). The
   image's WORKDIR is "/", so that resolved to "/parsers" (doesn't exist)
   instead of the real "/opt/arkime/parsers" -- capture indexed every
   session with zero protocol dissectors.
2. Both arkime-capture and arkime-viewer mounted geo data from
   /opt/stacks/apiary/arkime/geo, a directory nothing ever populated (a
   dead, never-automated db-ip.com process). The real, currently-refreshed
   MaxMind databases live in /opt/stacks/apiary/analysis/geoip, already
   used by Elasticsearch and hp-geoipupdate.

This test pins: config.ini sets an absolute parsersDir and geoLite2* paths
matching real GeoLite2 filenames; compose.yml mounts both Arkime services'
geo volume from analysis/geoip; and geoipupdate fetches a Country edition
so Arkime's geoLite2Country points at a database dedicated to that purpose
rather than an unconfirmed City-as-superset assumption.
"""
import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ELK_DIR = REPO_ROOT / "arcane" / "home" / "honeypot-elk"
CONFIG_INI = ELK_DIR / "arkime" / "config.ini"
ELK_COMPOSE = ELK_DIR / "compose.yml"
INIT_COMPOSE = REPO_ROOT / "arcane" / "home" / "honeypot-init" / "compose.yml"

COMMENT_LINE = re.compile(r"^\s*#")


def _stripped_lines(path):
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not COMMENT_LINE.match(line.strip())
    ]


def _ini_value(path, key):
    pattern = re.compile(rf"^{re.escape(key)}=(.*)$")
    for line in _stripped_lines(path):
        match = pattern.match(line.strip())
        if match:
            return match.group(1).strip()
    return None


def test_files_exist():
    assert CONFIG_INI.exists(), f"missing {CONFIG_INI}"
    assert ELK_COMPOSE.exists(), f"missing {ELK_COMPOSE}"
    assert INIT_COMPOSE.exists(), f"missing {INIT_COMPOSE}"


def test_parsers_dir_is_absolute():
    value = _ini_value(CONFIG_INI, "parsersDir")
    assert value == "/opt/arkime/parsers", (
        f"config.ini parsersDir should be the absolute /opt/arkime/parsers -- the "
        f"image's WORKDIR is '/', so the relative default ('./parsers') resolves to "
        f"'/parsers' and arkime_parsers_load() fails silently (#2713), got {value!r}"
    )


def test_geo_paths_point_at_real_maxmind_filenames():
    country = _ini_value(CONFIG_INI, "geoLite2Country")
    asn = _ini_value(CONFIG_INI, "geoLite2ASN")
    assert country == "/opt/arkime/geo/GeoLite2-Country.mmdb", (
        f"geoLite2Country must name a real GeoLite2 filename under the mounted geo "
        f"dir, got {country!r} (#2713)"
    )
    assert asn == "/opt/arkime/geo/GeoLite2-ASN.mmdb", (
        f"geoLite2ASN must name a real GeoLite2 filename under the mounted geo dir, "
        f"got {asn!r} (#2713)"
    )


def test_no_lingering_dbip_style_geo_filenames():
    text = "\n".join(_stripped_lines(CONFIG_INI))
    for stale in ("/opt/arkime/geo/country.mmdb", "/opt/arkime/geo/asn.mmdb"):
        assert stale not in text, (
            f"config.ini still references the dead db-ip-style path {stale!r} (#2713)"
        )


def test_arkime_services_mount_geo_from_the_populated_directory():
    text = "\n".join(_stripped_lines(ELK_COMPOSE))
    mounts = re.findall(
        r"^\s*-\s*(\S+):/opt/arkime/geo:ro\s*$", text, flags=re.MULTILINE
    )
    assert len(mounts) == 2, (
        f"expected exactly 2 /opt/arkime/geo mounts (capture + viewer) in "
        f"{ELK_COMPOSE.name}, found {len(mounts)}: {mounts}"
    )
    for source in mounts:
        assert source == "/opt/stacks/apiary/analysis/geoip", (
            f"arkime geo mount must source from /opt/stacks/apiary/analysis/geoip -- "
            f"the directory hp-geoipupdate actually refreshes -- not the dead "
            f"arkime/geo/ path (#2713), got {source!r}"
        )


def test_geoipupdate_fetches_a_country_edition():
    text = "\n".join(_stripped_lines(INIT_COMPOSE))
    match = re.search(r"GEOIPUPDATE_EDITION_IDS=([^\n\"']*)", text)
    assert match, f"GEOIPUPDATE_EDITION_IDS not found in {INIT_COMPOSE}"
    editions = match.group(1).split()
    assert "GeoLite2-Country" in editions, (
        f"Arkime's geoLite2Country points at a GeoLite2-Country.mmdb -- "
        f"GEOIPUPDATE_EDITION_IDS must fetch that edition, not just City/ASN "
        f"(#2713), got {editions}"
    )
    assert "GeoLite2-ASN" in editions, (
        f"geoLite2ASN still needs the ASN edition fetched, got {editions}"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
