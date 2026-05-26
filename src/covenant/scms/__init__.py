"""SCM client implementations for covenant.

Each SCM module exposes the same three read-only operations against a
configurable base URL so the live and mock paths are identical:

- ``recon_repo(query)`` -> list of normalized repo dicts
- ``recon_code(query)`` -> list of normalized code-hit dicts
- ``validate_token()`` -> {"scopes": [...], "user": ..., "admin": bool}

Normalized repo/code dicts always carry ``name``, ``visibility`` and ``url``.
"""

from .github import GitHubClient
from .gitlab import GitLabClient
from .bitbucket import BitbucketClient

CLIENTS = {
    "github": GitHubClient,
    "gitlab": GitLabClient,
    "bitbucket": BitbucketClient,
}

__all__ = ["GitHubClient", "GitLabClient", "BitbucketClient", "CLIENTS"]
