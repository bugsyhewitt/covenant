"""GitHub SCM client (cloud GitHub for v0.1; GHE deferred to v0.2)."""

from __future__ import annotations

from .base import BaseSCMClient, SCMError


class GitHubClient(BaseSCMClient):
    default_base_url = "https://api.github.com"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "covenant",
        }

    def recon_repo(self, query: str) -> list[dict]:
        data = self._get("/search/repositories", params={"q": query}).json()
        results = []
        for item in data.get("items", []):
            results.append(
                {
                    "name": item.get("full_name") or item.get("name"),
                    "visibility": item.get(
                        "visibility",
                        "private" if item.get("private") else "public",
                    ),
                    "url": item.get("html_url"),
                    "description": item.get("description"),
                }
            )
        return results

    def recon_code(self, query: str) -> list[dict]:
        data = self._get("/search/code", params={"q": query}).json()
        results = []
        for item in data.get("items", []):
            repo = item.get("repository", {})
            results.append(
                {
                    "name": item.get("name"),
                    "path": item.get("path"),
                    "visibility": "private" if repo.get("private") else "public",
                    "url": item.get("html_url"),
                    "repository": repo.get("name"),
                }
            )
        return results

    def validate_token(self) -> dict:
        resp = self._get("/user")
        user = resp.json()
        scope_header = resp.headers.get("X-OAuth-Scopes", "")
        scopes = [s.strip() for s in scope_header.split(",") if s.strip()]
        login = user.get("login")
        if not login:
            raise SCMError("token validation returned no user identity")
        return {
            "scopes": scopes,
            "user": login,
            "admin": bool(user.get("site_admin", False)),
        }
