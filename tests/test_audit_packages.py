"""Tests for validate-token --audit-packages (declared dependency inventory).

Covers the read-only inventory of the package dependencies a captured token's
reachable repos DECLARE in their manifest files (package.json, requirements.txt,
pyproject.toml, Pipfile, go.mod, Gemfile, pom.xml). Where
``--audit-dependabot-alerts`` reports the KNOWN-vulnerable subset a provider
scanner has already flagged, this reports the FULL declared dependency surface —
the software-supply-chain inventory an operator needs before triaging which
package is vulnerable, typosquatted, or abandoned.

The feature is additive: the v0.1 validate-token fields stay intact, the
``packages`` array only appears when ``--audit-packages`` is passed, and the
normalized ``{"repo", "manifest", "ecosystem", "package", "version"}`` shape is
uniform across all three providers. Unlike ``--audit-dependabot-alerts`` (a
no-op on Bitbucket Cloud), this works on all three SCMs because it reads
manifests directly. Only package names + declared versions are surfaced — never
lockfile graphs, source, or any credential a manifest might contain.

Two layers are exercised:
  * unit — the pure ``parse_manifest`` dispatcher and each per-ecosystem parser,
    plus each client's ``audit_packages`` against the in-process mock server,
    asserting the normalized shape, ecosystem mapping, and declared-version
    capture.
  * e2e — the CLI flag end-to-end, asserting ``packages`` is present only under
    the flag and absent otherwise, composes with the other --enumerate-*/--audit-*
    flags, respects the scope guardrail (exit 2), and is documented in --help.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.base import PACKAGE_MANIFESTS, parse_manifest
from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_PKG_FIELDS = {"repo", "manifest", "ecosystem", "package", "version"}


def _run(args: list[str], env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("COVENANT_TOKEN", "ghp_faketoken123")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "covenant", *args],
        capture_output=True,
        text=True,
        env=env,
    )


# --- unit: the supported-manifest registry ----------------------------------


def test_package_manifests_cover_the_documented_ecosystems():
    by_name = dict(PACKAGE_MANIFESTS)
    assert by_name["package.json"] == "npm"
    assert by_name["requirements.txt"] == "pip"
    assert by_name["pyproject.toml"] == "pip"
    assert by_name["Pipfile"] == "pip"
    assert by_name["go.mod"] == "go"
    assert by_name["Gemfile"] == "rubygems"
    assert by_name["pom.xml"] == "maven"


# --- unit: the pure parsers --------------------------------------------------


def test_parse_package_json_reads_all_dependency_sections():
    text = json.dumps(
        {
            "dependencies": {"left-pad": "^1.3.0", "lodash": "4.17.21"},
            "devDependencies": {"jest": "^29.0.0"},
            "peerDependencies": {"react": ">=18"},
        }
    )
    pkgs = {p["package"]: p["version"] for p in parse_manifest("package.json", text)}
    assert pkgs["left-pad"] == "^1.3.0"
    assert pkgs["lodash"] == "4.17.21"
    assert pkgs["jest"] == "^29.0.0"
    assert pkgs["react"] == ">=18"


def test_parse_requirements_txt_pins_and_bare_and_skips_directives():
    text = (
        "requests==2.31.0\n"
        "flask>=2.0\n"
        "bare-pkg\n"
        "pkg-with-extra[extra]==1.0\n"
        "# a comment\n"
        "\n"
        "-r other-requirements.txt\n"
        "django==4.2  ; python_version >= '3.10'\n"
    )
    pkgs = {p["package"]: p["version"] for p in parse_manifest("requirements.txt", text)}
    assert pkgs["requests"] == "2.31.0"
    assert pkgs["flask"] == "2.0"  # declared lower bound captured
    assert pkgs["bare-pkg"] is None  # no operator -> unpinned
    assert pkgs["pkg-with-extra"] == "1.0"
    assert pkgs["django"] == "4.2"  # env marker stripped
    assert "other-requirements.txt" not in pkgs  # -r directive skipped


def test_parse_pyproject_toml_reads_pep621_and_poetry():
    text = (
        "[project]\n"
        'dependencies = ["httpx>=0.27", "click==8.1.7"]\n'
        "\n"
        "[tool.poetry.dependencies]\n"
        'python = "^3.13"\n'
        'rich = "^13.0"\n'
    )
    pkgs = {p["package"]: p["version"] for p in parse_manifest("pyproject.toml", text)}
    assert pkgs["httpx"] == "0.27"  # declared lower bound captured
    assert pkgs["click"] == "8.1.7"
    assert pkgs["rich"] == "^13.0"
    assert "python" not in pkgs  # interpreter constraint, not a package


def test_parse_pipfile_reads_packages_and_dev_packages():
    text = (
        "[packages]\n"
        'requests = "==2.31.0"\n'
        'flask = "*"\n'
        "\n"
        "[dev-packages]\n"
        'pytest = {version = "==8.0"}\n'
    )
    pkgs = {p["package"]: p["version"] for p in parse_manifest("Pipfile", text)}
    assert pkgs["requests"] == "==2.31.0"
    assert pkgs["flask"] is None  # '*' means any -> unpinned
    assert pkgs["pytest"] == "==8.0"


def test_parse_go_mod_single_and_block_form_with_indirect():
    text = (
        "module example.com/app\n\n"
        "go 1.22\n\n"
        "require github.com/spf13/cobra v1.8.0\n\n"
        "require (\n"
        "\tgithub.com/pkg/errors v0.9.1\n"
        "\tgolang.org/x/sync v0.7.0 // indirect\n"
        ")\n"
    )
    pkgs = {p["package"]: p["version"] for p in parse_manifest("go.mod", text)}
    assert pkgs["github.com/spf13/cobra"] == "v1.8.0"
    assert pkgs["github.com/pkg/errors"] == "v0.9.1"
    assert pkgs["golang.org/x/sync"] == "v0.7.0"  # indirect still inventoried


def test_parse_gemfile_with_and_without_version_constraints():
    text = (
        "source 'https://rubygems.org'\n"
        "ruby '3.2.0'\n"
        "gem 'rails', '~> 7.0'\n"
        "gem 'puma'\n"
        "# gem 'commented-out'\n"
    )
    pkgs = {p["package"]: p["version"] for p in parse_manifest("Gemfile", text)}
    assert pkgs["rails"] == "~> 7.0"
    assert pkgs["puma"] is None
    assert "commented-out" not in pkgs


def test_parse_pom_xml_uses_group_artifact_coordinate():
    text = (
        "<project>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.apache.commons</groupId>\n"
        "      <artifactId>commons-lang3</artifactId>\n"
        "      <version>3.12.0</version>\n"
        "    </dependency>\n"
        "    <dependency>\n"
        "      <groupId>com.google.guava</groupId>\n"
        "      <artifactId>guava</artifactId>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    pkgs = {p["package"]: p["version"] for p in parse_manifest("pom.xml", text)}
    assert pkgs["org.apache.commons:commons-lang3"] == "3.12.0"
    assert pkgs["com.google.guava:guava"] is None  # managed version


def test_parse_manifest_unknown_or_garbage_returns_empty():
    assert parse_manifest("Cargo.toml", "anything") == []
    assert parse_manifest("package.json", "{not valid json") == []
    assert parse_manifest("pyproject.toml", "not = valid = toml = [") == []


# --- unit: each client's audit_packages returns the normalized shape --------


def test_github_audit_packages_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_packages()
    assert records, "expected at least one declared package"
    for r in records:
        assert set(r.keys()) == _PKG_FIELDS
        assert r["repo"]
        assert r["manifest"] in dict(PACKAGE_MANIFESTS)
    by_pkg = {(r["package"], r["manifest"]): r for r in records}
    # spellbook package.json (npm) + requirements.txt (pip).
    assert by_pkg[("left-pad", "package.json")]["ecosystem"] == "npm"
    assert by_pkg[("left-pad", "package.json")]["version"] == "^1.3.0"
    assert by_pkg[("requests", "requirements.txt")]["ecosystem"] == "pip"
    assert by_pkg[("requests", "requirements.txt")]["version"] == "2.31.0"


def test_github_audit_packages_repo_without_manifest_yields_no_rows():
    """A repo with no recognized manifest contributes no package rows."""

    class _NoManifestClient(GitHubClient):
        def _reachable_repos(self, max_pages=10):
            return ["acme-corp/bare"]

        def _fetch_file_content(self, path):  # every manifest probe absent
            return None

    client = _NoManifestClient(token="ghp_x", base_url="http://127.0.0.1:1")
    assert client.audit_packages() == []


def test_gitlab_audit_packages_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    records = client.audit_packages()
    assert records, "expected at least one declared package"
    for r in records:
        assert set(r.keys()) == _PKG_FIELDS
    by_pkg = {r["package"]: r for r in records}
    # mock project ships a go.mod (go ecosystem).
    assert by_pkg["github.com/pkg/errors"]["ecosystem"] == "go"
    assert by_pkg["github.com/pkg/errors"]["version"] == "v0.9.1"
    assert by_pkg["github.com/pkg/errors"]["manifest"] == "go.mod"


def test_bitbucket_audit_packages_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    records = client.audit_packages()
    assert records, "expected at least one declared package"
    for r in records:
        assert set(r.keys()) == _PKG_FIELDS
    by_pkg = {r["package"]: r for r in records}
    # mock repo ships a Gemfile (rubygems ecosystem). Bitbucket has no
    # dependency-alert API, so this is the only dependency surface there.
    assert by_pkg["rails"]["ecosystem"] == "rubygems"
    assert by_pkg["rails"]["version"] == "~> 7.0"
    assert by_pkg["rails"]["manifest"] == "Gemfile"
    assert by_pkg["puma"]["version"] is None


# --- e2e: the CLI flag adds a 'packages' array (only when requested) ---------


def test_github_validate_token_audit_packages_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-packages",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    # v0.1 fields untouched.
    assert "scopes" in payload and "user" in payload and "admin" in payload
    # New additive field present and well-formed.
    assert "packages" in payload
    ecosystems = {p["ecosystem"] for p in payload["packages"]}
    assert {"npm", "pip"} <= ecosystems


def test_validate_token_without_flag_has_no_packages_key(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "packages" not in payload


def test_gitlab_validate_token_audit_packages_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-packages",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "packages" in payload
    assert any(p["ecosystem"] == "go" for p in payload["packages"])


def test_bitbucket_validate_token_audit_packages_cli(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-packages",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "packages" in payload
    assert any(p["ecosystem"] == "rubygems" for p in payload["packages"])


def test_audit_packages_composes_with_other_audits(github_mock, scope_file):
    """--audit-packages composes with the other additive flags; all arrays
    appear together."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-branch-protection",
            "--audit-codeowners",
            "--audit-packages",
            "--enumerate-collaborators",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert (
        "branch_protection" in payload
        and "codeowners" in payload
        and "packages" in payload
        and "collaborators" in payload
    )


def test_audit_packages_respects_scope_guardrail(scope_file):
    """--audit-packages is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-packages",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_packages():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-packages" in proc.stdout
