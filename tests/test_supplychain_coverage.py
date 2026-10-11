"""Supply-chain coverage: expanded typosquat lists and gem/composer/maven installs."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from supplychain.ecosystems.detector import detect_install
from supplychain.scoring import osv_lookup
from supplychain.scoring.typosquat import (
    ECOSYSTEM_REGISTRY,
    POPULAR_PACKAGES,
    _REGISTRY_LISTS,
    check_typosquat,
)


# ── typosquat: lists ────────────────────────────────────────────────────

def test_lists_are_meaningfully_sized():
    sizes = {reg: len(set(names)) for reg, names in _REGISTRY_LISTS.items()}
    assert sizes["npm"] >= 250
    assert sizes["pypi"] >= 250
    assert sizes["crates"] >= 200
    assert sizes["go"] >= 150
    assert min(sizes["rubygems"], sizes["packagist"], sizes["maven"]) >= 60


@pytest.mark.parametrize("registry", sorted(_REGISTRY_LISTS))
def test_no_popular_package_flags_itself_or_a_sibling(registry):
    eco = next(e for e, r in ECOSYSTEM_REGISTRY.items() if r == registry)
    flagged = [n for n in _REGISTRY_LISTS[registry] if check_typosquat(n, eco)]
    assert flagged == []


def test_every_ecosystem_label_has_a_list():
    for eco in ("npm", "pnpm", "yarn", "bun", "pip", "uv", "pypi", "cargo", "go",
                "gem", "composer", "maven"):
        assert POPULAR_PACKAGES[eco], eco


# ── typosquat: known squats are caught ──────────────────────────────────

@pytest.mark.parametrize("name,eco,target", [
    ("reqeusts", "pip", "requests"),
    ("requets", "pypi", "requests"),
    ("colourama", "pip", "colorama"),
    ("urlib3", "pip", "urllib3"),
    ("python3-dateutil", "pip", "python-dateutil"),   # 2019 PyPI squat
    ("pythondateutil", "pip", "python-dateutil"),
    ("beautifulsoup", "pip", "beautifulsoup4"),
    ("djanga", "pip", "django"),
    ("lodahs", "npm", "lodash"),
    ("loadsh", "npm", "lodash"),
    ("crossenv", "npm", "cross-env"),                 # 2017 npm squat
    ("cross-env.js", "npm", "cross-env"),
    ("electorn", "npm", "electron"),
    ("mongose", "npm", "mongoose"),
    ("jquerry", "yarn", "jquery"),
    ("axois", "pnpm", "axios"),
    ("tokioo", "cargo", "tokio"),
    ("serde-jsom", "cargo", "serde_json"),
    ("github.com/strechr/testify", "go", "github.com/stretchr/testify"),
    ("github.com/boltdb-go/bolt", "go", "github.com/boltdb/bolt"),   # 2025 Go squat
    ("github.com/gin-gonik/gin", "go", "github.com/gin-gonic/gin"),
    ("nokogirl", "gem", "nokogiri"),
    ("rspec-rials", "gem", "rspec-rails"),
    ("laravell/framework", "composer", "laravel/framework"),
    ("guzzelhttp/guzzle", "composer", "guzzlehttp/guzzle"),
    ("com.fasterxm1.jackson.core:jackson-databind", "maven",
     "com.fasterxml.jackson.core:jackson-databind"),
])
def test_known_typosquats_flagged(name, eco, target):
    assert check_typosquat(name, eco) == target


# ── typosquat: legit packages are not flagged ───────────────────────────

@pytest.mark.parametrize("name,eco", [
    # popular packages themselves, and PEP 503 / crates.io spellings of them
    ("requests", "pip"), ("Django", "pip"), ("python_dateutil", "pip"),
    ("PyYAML", "pip"), ("serde-json", "cargo"), ("react", "npm"),
    ("cross-env", "npm"), ("colorama", "pip"),
    # one edit from a popular name, but popular in their own right
    ("chai", "npm"), ("preact", "npm"), ("safer-buffer", "npm"), ("bowser", "npm"),
    ("pypdf2", "pip"), ("tomli-w", "pip"), ("authlib", "pip"), ("mysql", "gem"),
    # short names have too many real neighbours to judge
    ("vuex", "npm"), ("six", "pip"), ("pgx", "npm"), ("rack", "gem"),
    # legit packages near popular ones
    ("numba", "pip"), ("aiofiles", "pip"), ("requests-mock", "pip"),
    ("react-dom-factories", "npm"), ("tokio-postgres", "cargo"),
    ("regex-syntax", "cargo"),
    # trusted npm scopes
    ("@radix-ui/react-id", "npm"), ("@types/babel__core", "npm"),
    # go: same-owner siblings and major-version suffixes
    ("golang.org/x/image", "go"), ("golang.org/x/vuln", "go"),
    ("github.com/redis/go-redis/v9", "go"), ("github.com/gin-contrib/cors", "go"),
    ("github.com/google/uuid@v1.6.0", "go"),
    # namespaced siblings
    ("symfony/http-client", "composer"), ("laravel/breeze", "composer"),
    ("org.springframework:spring-beans", "maven"),
    ("org.slf4j:slf4j-simple", "maven"),
    ("my-custom-xyz-lib", "npm"),
])
def test_legit_packages_not_flagged(name, eco):
    assert check_typosquat(name, eco) is None


def test_bounded_distance_matches_full_distance():
    import random

    from supplychain.scoring.typosquat import _bounded_distance, _edit_distance

    rng = random.Random(555)
    for _ in range(3000):
        a = "".join(rng.choice("abcd") for _ in range(rng.randint(0, 9)))
        b = "".join(rng.choice("abcd") for _ in range(rng.randint(0, 9)))
        for limit in (0, 1, 2, 3):
            full = _edit_distance(a, b)
            assert _bounded_distance(a, b, limit) == min(full, limit + 1), (a, b, limit)


def test_unknown_ecosystem_is_ignored():
    assert check_typosquat("reqeusts", "nuget") is None


# ── install detection: RubyGems ─────────────────────────────────────────

def test_gem_install():
    ev = detect_install(["gem", "install", "rails"])
    assert ev.ecosystem == "gem"
    assert [(p.name, p.version) for p in ev.packages] == [("rails", "")]


def test_gem_install_with_version_flag():
    ev = detect_install(["gem", "install", "nokogiri", "-v", "1.15.4"])
    assert [(p.name, p.version) for p in ev.packages] == [("nokogiri", "1.15.4")]
    ev = detect_install(["gem", "install", "nokogiri", "--version=1.15.4"])
    assert ev.packages[0].version == "1.15.4"


def test_gem_install_colon_version_and_range():
    ev = detect_install(["gem", "install", "rails:7.1.3"])
    assert [(p.name, p.version) for p in ev.packages] == [("rails", "7.1.3")]
    ev = detect_install(["gem", "install", "rails", "-v", "~> 7.1"])
    assert ev.packages[0].version == ""


def test_gem_remote_flag_does_not_eat_package():
    # gem's -r is --remote (no value) -- unlike pip's -r FILE.
    ev = detect_install(["gem", "install", "-r", "rails"])
    assert [p.name for p in ev.packages] == ["rails"]


def test_gem_custom_source():
    ev = detect_install(["gem", "install", "rails", "--source", "https://gems.evil.example"])
    assert ev.custom_registry == "https://gems.evil.example"
    assert [p.name for p in ev.packages] == ["rails"]


def test_bundle_add():
    ev = detect_install(["bundle", "add", "sidekiq", "--version", "7.2.0", "--group", "dev"])
    assert ev.ecosystem == "gem"
    assert [(p.name, p.version) for p in ev.packages] == [("sidekiq", "7.2.0")]


def test_bundle_add_from_vcs_is_not_registry():
    ev = detect_install(["bundle", "add", "mygem", "--github", "someone/mygem"])
    assert [(p.name, p.source) for p in ev.packages] == [("mygem", "git")]


def test_bundle_install_is_not_a_package_install():
    assert detect_install(["bundle", "install"]) is None


# ── install detection: Composer ─────────────────────────────────────────

def test_composer_require():
    ev = detect_install(["composer", "require", "monolog/monolog"])
    assert ev.ecosystem == "composer"
    assert [(p.name, p.version) for p in ev.packages] == [("monolog/monolog", "")]


@pytest.mark.parametrize("argv,version", [
    (["composer", "require", "monolog/monolog:3.5.0"], "3.5.0"),
    (["composer", "require", "monolog/monolog=3.5.0"], "3.5.0"),
    (["composer", "require", "monolog/monolog", "3.5.0"], "3.5.0"),
    (["composer", "require", "monolog/monolog:v3.5.0"], "3.5.0"),
    (["composer", "require", "monolog/monolog:^3.5"], ""),
])
def test_composer_versions(argv, version):
    ev = detect_install(argv)
    assert [(p.name, p.version) for p in ev.packages] == [("monolog/monolog", version)]


def test_composer_global_dev_and_platform_packages():
    ev = detect_install(["composer", "global", "require", "--dev", "phpunit/phpunit", "ext-json"])
    assert [p.name for p in ev.packages] == ["phpunit/phpunit"]
    ev = detect_install(["composer", "require", "-d", "app", "Laravel/Sanctum"])
    assert [p.name for p in ev.packages] == ["laravel/sanctum"]


def test_composer_install_is_not_a_package_install():
    assert detect_install(["composer", "install"]) is None


# ── install detection: Maven ────────────────────────────────────────────

def test_mvn_dependency_get():
    ev = detect_install(["mvn", "-q", "dependency:get",
                         "-Dartifact=org.apache.logging.log4j:log4j-core:2.14.1"])
    assert ev.ecosystem == "maven"
    assert [(p.name, p.version) for p in ev.packages] == [
        ("org.apache.logging.log4j:log4j-core", "2.14.1")]


def test_mvn_dependency_get_split_coordinates_and_repo():
    ev = detect_install(["./mvnw", "dependency:get", "-DgroupId=com.google.guava",
                         "-DartifactId=guava", "-Dversion=33.0-jre",
                         "-DremoteRepositories=https://repo.evil.example/maven2"])
    assert [(p.name, p.version) for p in ev.packages] == [("com.google.guava:guava", "33.0-jre")]
    assert ev.custom_registry == "https://repo.evil.example/maven2"


def test_mvn_build_is_not_an_install():
    assert detect_install(["mvn", "clean", "install"]) is None
    assert detect_install(["gradle", "build"]) is None


# ── existing ecosystems unchanged ───────────────────────────────────────

def test_pip_requirement_flag_still_consumes_value():
    ev = detect_install(["pip", "install", "-r", "requirements.txt", "flask"])
    assert [p.name for p in ev.packages] == ["flask"]


# ── OSV wiring ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("eco,osv", [
    ("gem", "RubyGems"), ("composer", "Packagist"), ("maven", "Maven"),
    ("npm", "npm"), ("pip", "PyPI"), ("cargo", "crates.io"), ("go", "Go"),
])
def test_osv_ecosystem_names(eco, osv):
    assert osv_lookup._osv_ecosystem(eco) == osv


def test_osv_query_uses_packagist_name():
    captured = {}

    def fake_post(url, body, timeout=4):
        captured.update(body)
        return {"vulns": []}

    osv_lookup._CACHE.clear()
    with patch.object(osv_lookup, "_post_json", fake_post):
        osv_lookup.fetch_vulns("monolog/monolog", "composer", "1.0.0")
    assert captured["package"] == {"name": "monolog/monolog", "ecosystem": "Packagist"}
    osv_lookup._CACHE.clear()


# ── end to end through the hook policy engine ──────────────────────────

@pytest.mark.parametrize("command,needle", [
    ("gem install nokogirl", "nokogiri"),
    ("composer require laravell/framework", "laravel/framework"),
    ("pip install colourama", "colorama"),
])
def test_policy_engine_flags_typosquat_installs(tmp_path, command, needle):
    from prismor.runtime.policy_engine import PolicyEngine

    engine = PolicyEngine(workspace=tmp_path)
    engine.supply_chain_install_check = True
    with patch("supplychain.scoring.engine.fetch_vulns", return_value=[]), \
         patch("supplychain.ecosystems.metadata._http_get", return_value=None), \
         patch("supplychain.scoring.safe_version.recommend_safe_version", return_value=None):
        findings = engine._check_supply_chain(command, 0, "")
    assert findings, command
    assert any(needle in (f.get("remediation") or "") for f in findings)
