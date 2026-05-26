"""Bitbucket Cloud SCM client (Bitbucket Server is EOL'd, out of scope)."""

from __future__ import annotations

from .base import BaseSCMClient, SCMError


class BitbucketClient(BaseSCMClient):
    default_base_url = "https://api.bitbucket.org"

    def _headers(self) -> dict[str, str]:
        # Bitbucket Cloud accepts an app-password / token as a Bearer token.
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": "covenant",
        }

    def recon_repo(self, query: str) -> list[dict]:
        data = self._get(
            "/2.0/repositories",
            params={"q": f'name~"{query}"', "role": "member"},
        ).json()
        results = []
        for item in data.get("values", []):
            links = item.get("links", {}).get("html", {})
            results.append(
                {
                    "name": item.get("full_name") or item.get("name"),
                    "visibility": "private" if item.get("is_private") else "public",
                    "url": links.get("href"),
                    "description": item.get("description"),
                }
            )
        return results

    def recon_code(self, query: str) -> list[dict]:
        # Bitbucket Cloud code search requires a workspace path; without one we
        # surface repos as the closest read-only equivalent for v0.1 parity.
        return self.recon_repo(query)

    def validate_token(self) -> dict:
        user = self._get("/2.0/user").json()
        username = user.get("username") or user.get("nickname")
        if not username:
            raise SCMError("token validation returned no user identity")
        admin = False
        scopes: list[str] = []
        try:
            perms = self._get("/2.0/user/permissions/repositories").json()
            for entry in perms.get("values", []):
                perm = entry.get("permission")
                if perm:
                    scopes.append(perm)
                if perm == "admin":
                    admin = True
        except SCMError:
            scopes = []
        return {"scopes": scopes, "user": username, "admin": admin}
