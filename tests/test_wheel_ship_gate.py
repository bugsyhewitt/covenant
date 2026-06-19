"""End-to-end wheel ship-gate for covenant v0.1.

Builds the wheel and sdist from the project root, spins up a single fresh
venv per test module, installs the wheel with full runtime deps, then asserts:

  - entry-point resolves and --help works
  - every first-class module imports from site-packages/ (not the working tree)
  - recon-repo produces a valid JSON envelope for all three SCMs against the
    bundled MockSCMServer
  - the scope guardrail refuses an out-of-scope target with exit code 2

Marked @pytest.mark.ship_gate so `pytest -m "not ship_gate"` skips these
and the bare `pytest` invocation (the v0.1 bar) includes them.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

# Ensure tests/ is on sys.path so mock_scm_server is importable.
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from mock_scm_server import MockSCMServer  # noqa: E402

TESTS_DIR = pathlib.Path(__file__).parent
PROJECT_ROOT = TESTS_DIR.parent
SCOPE_FILE = str(TESTS_DIR / "fixtures" / "scope.txt")

pytestmark = pytest.mark.ship_gate


# ---------------------------------------------------------------------------
# Module-scoped fixtures: build the wheel once; create one fresh venv shared
# across all ship-gate tests so the suite stays within a reasonable runtime.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory):
    """Build covenant wheel + sdist into a temp dir; return the .whl path."""
    dist_dir = tmp_path_factory.mktemp("sg_dist")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--sdist",
            "--outdir",
            str(dist_dir),
        ],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"python -m build failed (exit {result.returncode}):\n{result.stderr}"
    )
    wheels = sorted(dist_dir.glob("covenant-*.whl"))
    sdists = sorted(dist_dir.glob("covenant-*.tar.gz"))
    assert wheels, f"no .whl produced under {dist_dir}"
    assert sdists, f"no .tar.gz produced under {dist_dir}"
    return wheels[0]


@pytest.fixture(scope="module")
def fresh_venv_bin(tmp_path_factory, built_wheel):
    """Create a fresh isolated venv, install the wheel, return its bin/ dir."""
    venv_root = tmp_path_factory.mktemp("sg_fresh_venv")
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_root)],
        check=True,
        capture_output=True,
    )
    pip = venv_root / "bin" / "pip"

    # Install the wheel — pulls in declared runtime deps:
    # httpx, PyGithub, python-gitlab, atlassian-python-api (and their transitive deps)
    result = subprocess.run(
        [str(pip), "install", str(built_wheel)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"wheel install failed (exit {result.returncode}):\n{result.stderr}"
    )

    # Install necromancer-patterns ([scan]/[dev] extra requirement)
    result = subprocess.run(
        [
            str(pip),
            "install",
            "necromancer-patterns @ git+https://github.com/bugsyhewitt/necromancer-patterns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"necromancer-patterns install failed (exit {result.returncode}):\n{result.stderr}"
    )

    return venv_root / "bin"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _run_covenant(bin_dir, args, env_extra=None):
    env = os.environ.copy()
    env["COVENANT_TOKEN"] = "ghp_faketoken123"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [str(bin_dir / "covenant"), *args],
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# Ship-gate tests
# ---------------------------------------------------------------------------


def test_wheel_builds_cleanly(built_wheel):
    """The wheel produced by python -m build must be non-empty and named correctly."""
    assert built_wheel.exists(), f"wheel path does not exist: {built_wheel}"
    assert built_wheel.stat().st_size > 0, "wheel file is empty"
    assert "covenant" in built_wheel.name
    # sdist was also asserted inside the built_wheel fixture
    sdist = built_wheel.parent / built_wheel.name.replace("-py3-none-any.whl", ".tar.gz")
    assert sdist.exists(), f"sdist not found at {sdist}"
    assert sdist.stat().st_size > 0, "sdist file is empty"


def test_wheel_installs_into_fresh_venv(fresh_venv_bin):
    """The fresh venv must have a covenant executable after wheel install."""
    covenant_bin = fresh_venv_bin / "covenant"
    assert covenant_bin.exists(), (
        f"covenant entry-point not created in {fresh_venv_bin}"
    )


def test_entry_point_resolves_from_fresh_venv(fresh_venv_bin):
    """covenant --help from the fresh venv exits 0 and lists all three SCMs."""
    result = subprocess.run(
        [str(fresh_venv_bin / "covenant"), "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"covenant --help failed (exit {result.returncode}):\n{result.stderr}"
    )
    for scm in ("github", "gitlab", "bitbucket"):
        assert scm in result.stdout, (
            f"'{scm}' not found in covenant --help output:\n{result.stdout}"
        )


def test_package_imports_from_installed_location(fresh_venv_bin):
    """covenant.__file__ must point to site-packages/, not the working-tree src/."""
    python = fresh_venv_bin / "python"
    result = subprocess.run(
        [
            str(python),
            "-c",
            (
                "import covenant; "
                "loc = covenant.__file__; "
                "assert 'site-packages' in loc, "
                "f'expected site-packages in {loc!r}'"
            ),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"import-location assertion failed:\n{result.stderr}"
    )


def test_public_surface_importable_from_fresh_venv(fresh_venv_bin):
    """Every advertised first-class module must import cleanly from site-packages/."""
    python = fresh_venv_bin / "python"
    modules = [
        "covenant",
        "covenant.cli",
        "covenant.scope",
        "covenant.secrets",
        "covenant.verify",
        "covenant.tokens",
        "covenant.scms.github",
        "covenant.scms.gitlab",
        "covenant.scms.bitbucket",
        "covenant.__main__",
    ]
    imports = "; ".join(f"import {m}" for m in modules)
    result = subprocess.run(
        [str(python), "-c", imports],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"public-surface import failed:\n{result.stderr}"
    )


def test_fresh_venv_recon_repo_github_against_mock(fresh_venv_bin):
    """recon-repo on github via fresh-venv wheel returns JSON with scm='github'."""
    with MockSCMServer("github") as server:
        result = _run_covenant(
            fresh_venv_bin,
            [
                "github",
                "recon-repo",
                "--scope-file", SCOPE_FILE,
                "--query", "test",
                "--token-env", "COVENANT_TOKEN",
                "--target-url", server.base_url,
            ],
        )
    assert result.returncode == 0, (
        f"github recon-repo failed (exit {result.returncode}):\n{result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert payload.get("scm") == "github", f"unexpected scm: {payload.get('scm')}"
    assert isinstance(payload.get("results"), list), "results must be a list"


def test_fresh_venv_recon_repo_gitlab_against_mock(fresh_venv_bin):
    """recon-repo on gitlab via fresh-venv wheel returns JSON with scm='gitlab'."""
    with MockSCMServer("gitlab") as server:
        result = _run_covenant(
            fresh_venv_bin,
            [
                "gitlab",
                "recon-repo",
                "--scope-file", SCOPE_FILE,
                "--query", "test",
                "--token-env", "COVENANT_TOKEN",
                "--target-url", server.base_url,
            ],
        )
    assert result.returncode == 0, (
        f"gitlab recon-repo failed (exit {result.returncode}):\n{result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert payload.get("scm") == "gitlab", f"unexpected scm: {payload.get('scm')}"
    assert isinstance(payload.get("results"), list), "results must be a list"


def test_fresh_venv_recon_repo_bitbucket_against_mock(fresh_venv_bin):
    """recon-repo on bitbucket via fresh-venv wheel returns JSON with scm='bitbucket'."""
    with MockSCMServer("bitbucket") as server:
        result = _run_covenant(
            fresh_venv_bin,
            [
                "bitbucket",
                "recon-repo",
                "--scope-file", SCOPE_FILE,
                "--query", "test",
                "--token-env", "COVENANT_TOKEN",
                "--target-url", server.base_url,
            ],
        )
    assert result.returncode == 0, (
        f"bitbucket recon-repo failed (exit {result.returncode}):\n{result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert payload.get("scm") == "bitbucket", f"unexpected scm: {payload.get('scm')}"
    assert isinstance(payload.get("results"), list), "results must be a list"


def test_fresh_venv_scope_guardrail_refuses_out_of_scope_target(fresh_venv_bin):
    """Out-of-scope target must exit 2 with a refusal message on stderr."""
    result = _run_covenant(
        fresh_venv_bin,
        [
            "github",
            "recon-repo",
            "--scope-file", SCOPE_FILE,
            "--query", "test",
            "--token-env", "COVENANT_TOKEN",
            "--target-url", "https://evil.example.com",
        ],
    )
    assert result.returncode == 2, (
        f"expected exit code 2 for out-of-scope target, got {result.returncode}:\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    combined = (result.stderr + result.stdout).lower()
    assert any(
        phrase in combined
        for phrase in ("not in scope", "out of scope", "scope", "refused", "refus")
    ), (
        f"no scope-refusal message found:\n"
        f"stderr={result.stderr!r}\nstdout={result.stdout!r}"
    )


def test_top_level_version_flag_works(fresh_venv_bin):
    """covenant --version at top level exits 0 and prints version string.

    Without the fix, this errors with 'the following arguments are required:
    {github,gitlab,bitbucket}' because --version was never wired into the
    top-level parser (see covenant-002-wire-top-level-version-flag.md).
    """
    covenant_bin = fresh_venv_bin / "covenant"
    assert covenant_bin.exists(), f"covenant entry-point not in {fresh_venv_bin}"
    result = subprocess.run(
        [str(covenant_bin), "--version"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"covenant --version failed (exit {result.returncode}):\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    assert "covenant 0.1.0" in result.stdout, (
        f"expected 'covenant 0.1.0' in --version output, got: {result.stdout!r}"
    )
    # --version must NOT require a subcommand (the whole point of this test).
    assert "{github,gitlab,bitbucket}" not in result.stderr, (
        f"--version should not require a subcommand, got stderr: {result.stderr!r}"
    )
