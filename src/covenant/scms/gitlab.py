"""GitLab SCM client (cloud + self-hosted via --target-url)."""

from __future__ import annotations

from .base import BaseSCMClient, SCMError


class GitLabClient(BaseSCMClient):
    default_base_url = "https://gitlab.com"

    def _headers(self) -> dict[str, str]:
        return {"PRIVATE-TOKEN": self.token, "User-Agent": "covenant"}

    def recon_repo(self, query: str) -> list[dict]:
        data = self._get(
            "/api/v4/projects",
            params={"search": query, "membership": "true"},
        ).json()
        results = []
        for item in data:
            results.append(
                {
                    "name": item.get("path_with_namespace") or item.get("name"),
                    "visibility": item.get("visibility", "private"),
                    "url": item.get("web_url"),
                    "description": item.get("description"),
                }
            )
        return results

    def recon_code(self, query: str) -> list[dict]:
        data = self._get(
            "/api/v4/search",
            params={"scope": "blobs", "search": query},
        ).json()
        results = []
        for item in data:
            results.append(
                {
                    "name": item.get("filename") or item.get("path"),
                    "path": item.get("path"),
                    "visibility": "unknown",
                    "url": item.get("web_url") or item.get("ref"),
                    "repository": item.get("project_id"),
                }
            )
        return results

    def recon_code_with_fragments(self, query: str) -> list[dict]:
        """Code search carrying matched-content fragments for secret scanning.

        GitLab's blob search response includes a ``data`` field containing the
        file content excerpt that matched the query.  We expose it as
        ``result["fragments"]`` for the caller to feed to
        :func:`covenant.secrets.scan_fragments`.
        """
        raw = self._get(
            "/api/v4/search",
            params={"scope": "blobs", "search": query},
        ).json()
        results = []
        for item in raw:
            # GitLab returns `data` as a string (the matched blob excerpt).
            fragment = item.get("data", "")
            fragments = [fragment] if fragment else []
            results.append(
                {
                    "name": item.get("filename") or item.get("path"),
                    "path": item.get("path"),
                    "visibility": "unknown",
                    "url": item.get("web_url") or item.get("ref"),
                    "repository": item.get("project_id"),
                    "fragments": fragments,
                }
            )
        return results

    def validate_token(self) -> dict:
        user = self._get("/api/v4/user").json()
        username = user.get("username")
        if not username:
            raise SCMError("token validation returned no user identity")
        scopes: list[str] = []
        try:
            pat = self._get("/api/v4/personal_access_tokens/self").json()
            scopes = list(pat.get("scopes", []))
        except SCMError:
            # Older GitLab / token types may not expose this endpoint.
            scopes = []
        return {
            "scopes": scopes,
            "user": username,
            "admin": bool(user.get("is_admin", False)),
        }
