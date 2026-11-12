"""Exchange a real GitHub Actions identity and query the global RawTree API."""
import base64
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

API = "https://api.rawtree.com"
GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class DemoFailure(Exception):
    pass


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(label, url, headers=None, data=None, expected=200):
    try:
        response = build_opener(NoRedirects).open(
            Request(url, headers=headers or {}, data=data), timeout=30
        )
    except HTTPError as error:
        response = error
    with response:
        if response.status != expected:
            raise DemoFailure(f"{label}: expected HTTP {expected}, got {response.status}")
        body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise DemoFailure(f"{label}: response exceeds size limit")
        return json.loads(body), response.headers


def check_routing(headers, deployment, region):
    if (headers.get("x-rawtree-routed-deployment-id") != deployment or
            headers.get("x-rawtree-routed-region") != region or
            headers.get("x-rawtree-routed-source") != "federation"):
        raise DemoFailure("Unexpected routing destination or source")


def check_claims(token, deployment, region):
    # Decode for assertions only; RawTree verifies the signature on the next request.
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    if claims.get("deployment_id") != deployment or claims.get("region") != region:
        raise DemoFailure("Issued token is missing the expected routing claims")
    if "federation_rule_id" in claims:
        raise DemoFailure("Issued token contains the redundant federation rule claim")
    lifetime = claims["exp"] - claims["iat"]
    if not 0 < lifetime <= 900:
        raise DemoFailure("Issued token lifetime is outside the expected 15-minute limit")
    return lifetime


def main():
    deployment = os.environ["RAWTREE_DEPLOYMENT_ID"]
    region = os.environ["RAWTREE_REGION"]
    provider_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    if urlsplit(provider_url).scheme != "https":
        raise DemoFailure("GitHub's OIDC endpoint must use HTTPS")
    separator = "&" if "?" in provider_url else "?"
    provider, _ = request(
        "GitHub OIDC", provider_url + separator + urlencode({"audience": os.environ["RAWTREE_AUDIENCE"]}),
        {"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]},
    )
    payload = provider["value"].split(".")[1]
    provider_claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    expected_claims = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": os.environ["RAWTREE_AUDIENCE"],
        "sub": os.environ["RAWTREE_SUBJECT"],
        "repository_id": os.environ["GITHUB_REPOSITORY_ID"],
        "repository_owner_id": os.environ["GITHUB_REPOSITORY_OWNER_ID"],
        "ref": "refs/heads/main",
        "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"],
    }
    mismatches = [key for key, expected in expected_claims.items() if provider_claims.get(key) != expected]
    if mismatches:
        raise DemoFailure("GitHub assertion does not match expected claims: " + ", ".join(mismatches))
    print("PASS: GitHub assertion claims match the configured trust conditions")
    form = urlencode({
        "grant_type": GRANT,
        "federation_rule_id": os.environ["RAWTREE_FEDERATION_RULE_ID"],
        "assertion": provider["value"],
        "deployment_id": deployment,
        "region": region,
    }).encode()
    form_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    access, routing = request("RawTree token exchange", API + "/oauth/token", form_headers, form)
    check_routing(routing, deployment, region)
    lifetime = check_claims(access["access_token"], deployment, region)
    if "refresh_token" in access:
        raise DemoFailure("Unexpected refresh token")
    print("PASS: GitHub OIDC exchanged for a short-lived RawTree token")
    print(f"PASS: deployment_id and region claims verified; token lifetime {lifetime}s")

    # No deployment/region hints: the router must use the issued JWT claims.
    result, routing = request("SQL query", API + "/v1/query", {
        "Authorization": "Bearer " + access["access_token"],
        "Content-Type": "application/json",
    }, json.dumps({"sql": "SELECT 42 AS value"}).encode())
    check_routing(routing, deployment, region)
    if result.get("data") != [{"value": 42}]:
        raise DemoFailure("Unexpected SQL query result")
    print('PASS: query routed from token claims; result [{"value": 42}]')

    replay, _ = request("Assertion replay", API + "/oauth/token", form_headers, form, expected=400)
    if replay.get("error") != "invalid_grant":
        raise DemoFailure("Assertion replay was not rejected as invalid_grant")
    print("PASS: reusing the GitHub assertion is rejected")


if __name__ == "__main__":
    try:
        main()
    except DemoFailure as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except (URLError, OSError, KeyError, ValueError, TypeError, IndexError) as error:
        # Never print response bodies, request objects, assertions, or access tokens.
        print(f"Demo failed ({type(error).__name__}); check configuration and connectivity.", file=sys.stderr)
        sys.exit(1)
