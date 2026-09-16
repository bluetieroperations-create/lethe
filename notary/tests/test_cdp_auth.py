"""Authenticated facilitator requests — the code that makes mainnet reachable.

Two things are being guarded. That the token is *correct*, checked against
PyJWT rather than against this module's own idea of a JWT, because a
hand-rolled JWS that only this repo can read is worthless. And that the
credential never leaks, because it is the one value here that can move money.
"""

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from lethe_notary.cdp_auth import (
    CdpAuthError,
    CdpAuthProvider,
    CdpCredentials,
    load_ed25519_key,
    mint_jwt,
)

pyjwt = pytest.importorskip("jwt", reason="PyJWT is the reference implementation")

KEY_ID = "1a2b3c4d-0000-0000-0000-abcdefabcdef"
DECODE_OPTS = {"verify_aud": False}


@pytest.fixture
def signing_key():
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def secret(signing_key):
    """A CDP-shaped secret: base64 of seed || public key."""
    return base64.b64encode(
        signing_key.private_bytes_raw() + signing_key.public_key().public_bytes_raw()
    ).decode()


# -- the token is a real JWT, by an independent implementation ---------------

def test_pyjwt_verifies_a_token_we_minted(signing_key, secret):
    """The claim this module makes is 'CDP will accept this'. We cannot ask
    CDP from a test, so the next best witness is the library everyone else
    uses. If PyJWT cannot verify it, neither will they."""
    token = mint_jwt(KEY_ID, load_ed25519_key(secret), "POST",
                     "https://api.cdp.coinbase.com/platform/v2/x402/settle")
    claims = pyjwt.decode(token, signing_key.public_key(),
                          algorithms=["EdDSA"], options=DECODE_OPTS)
    assert claims["sub"] == KEY_ID
    assert claims["iss"] == "cdp"
    assert claims["uris"] == ["POST api.cdp.coinbase.com/platform/v2/x402/settle"]


def test_the_header_names_the_key_and_the_algorithm(signing_key, secret):
    token = mint_jwt(KEY_ID, load_ed25519_key(secret), "GET", "https://h/supported")
    header = pyjwt.get_unverified_header(token)
    assert header["alg"] == "EdDSA"
    assert header["kid"] == KEY_ID
    assert header["typ"] == "JWT"


def test_a_tampered_claim_breaks_the_signature(signing_key, secret):
    """Not a property of our code so much as proof we are really signing: if
    the signature did not cover the claims, an attacker could widen `uris`."""
    token = mint_jwt(KEY_ID, load_ed25519_key(secret), "GET", "https://h/supported")
    head, payload, sig = token.split(".")
    swapped = "AA" if payload[-2:] != "AA" else "BB"
    with pytest.raises(pyjwt.InvalidSignatureError):
        pyjwt.decode(f"{head}.{payload[:-2]}{swapped}.{sig}",
                     signing_key.public_key(), algorithms=["EdDSA"],
                     options={**DECODE_OPTS, "verify_exp": False})


def test_a_token_expires(signing_key, secret):
    """The TTL is the reason a leaked token is survivable. If `exp` were
    missing or far out, a token captured from a log would stay usable."""
    old = mint_jwt(KEY_ID, load_ed25519_key(secret), "GET", "https://h/supported",
                   now=int(time.time()) - 3600)
    with pytest.raises(pyjwt.ExpiredSignatureError):
        pyjwt.decode(old, signing_key.public_key(), algorithms=["EdDSA"],
                     options=DECODE_OPTS)


def test_the_ttl_is_two_minutes_not_a_day(signing_key, secret):
    token = mint_jwt(KEY_ID, load_ed25519_key(secret), "GET", "https://h/s", now=1000)
    claims = pyjwt.decode(token, signing_key.public_key(), algorithms=["EdDSA"],
                          options={**DECODE_OPTS, "verify_exp": False})
    assert claims["exp"] - claims["nbf"] == 120


# -- the token is narrow --------------------------------------------------

def test_the_token_names_the_exact_request_it_authorizes(secret):
    """`uris` is what stops a token minted for /supported being replayed
    against /settle. Built from the URL actually being requested, so it stays
    right if the facilitator's endpoint layout changes."""
    key = load_ed25519_key(secret)
    base = "https://api.cdp.coinbase.com/platform/v2/x402"
    seen = {
        suffix: json.loads(base64.urlsafe_b64decode(
            mint_jwt(KEY_ID, key, method, base + suffix).split(".")[1] + "=="
        ))["uris"][0]
        for method, suffix in (("POST", "/settle"), ("POST", "/verify"),
                               ("GET", "/supported"))
    }
    assert seen["/settle"] == "POST api.cdp.coinbase.com/platform/v2/x402/settle"
    assert seen["/verify"] == "POST api.cdp.coinbase.com/platform/v2/x402/verify"
    assert seen["/supported"] == "GET api.cdp.coinbase.com/platform/v2/x402/supported"
    assert len(set(seen.values())) == 3


def _uris(token):
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))["uris"]


@pytest.mark.parametrize("url,expected", [
    # The ordinary case, and the only one CDP itself exercises.
    ("https://api.cdp.coinbase.com/x/supported", "api.cdp.coinbase.com/x/supported"),
    # A non-default port is part of the authority and must survive.
    ("https://facilitator.local:8443/x/supported", "facilitator.local:8443/x/supported"),
    # Case is preserved rather than normalized, because the facilitator
    # compares against what it computed, not against what we think is tidier.
    ("https://API.Example.COM/x/supported", "API.Example.COM/x/supported"),
    # An IPv6 authority keeps its brackets. Without them it is not a host.
    ("https://[::1]:8402/x/supported", "[::1]:8402/x/supported"),
])
def test_the_uri_matches_what_cdps_own_client_would_sign(secret, url, expected):
    """CDP's client signs `urlparse(url).netloc`. Anything that normalizes
    that — dropping a port, lowercasing, unwrapping an IPv6 address — produces
    a token the facilitator computes differently and rejects, with a 401 that
    explains nothing.

    Found auditing this change: `.hostname` was used first, which does all
    three. Measured against `netloc` on five URLs, four diverged.
    """
    assert _uris(mint_jwt(KEY_ID, load_ed25519_key(secret), "GET", url)) == [f"GET {expected}"]


def test_a_credential_in_the_facilitator_url_never_reaches_the_token(secret):
    """It would otherwise ride along into a header sent to the facilitator and
    written to its logs.

    The password is spelled out at length on purpose: a token is mostly random
    base64, so asserting a two-letter secret is absent fails about 2% of the
    time by chance. Written that way first, and caught by one red run.
    """
    token = mint_jwt(KEY_ID, load_ed25519_key(secret), "GET",
                     "https://someuser:l0ngEnoughT0N0tC0llide@api.example.com:8443/x/supported")
    assert _uris(token) == ["GET api.example.com:8443/x/supported"]
    assert "l0ngEnoughT0N0tC0llide" not in token
    assert "someuser" not in token


def test_each_token_carries_its_own_nonce(secret):
    key = load_ed25519_key(secret)
    nonces = {pyjwt.get_unverified_header(
        mint_jwt(KEY_ID, key, "GET", "https://h/s"))["nonce"] for _ in range(20)}
    assert len(nonces) == 20


def test_a_url_with_no_host_is_refused(secret):
    with pytest.raises(CdpAuthError):
        mint_jwt(KEY_ID, load_ed25519_key(secret), "GET", "/supported")


# -- the provider wires all four endpoints --------------------------------

def test_the_provider_mints_a_distinct_bearer_for_each_endpoint(secret, signing_key):
    """x402's AuthProvider protocol returns all four endpoints' headers in one
    call without saying which is about to be used, so all four must be right."""
    headers = CdpAuthProvider(CdpCredentials(key_id=KEY_ID, secret=secret),
                              "https://api.example.com/x402/").get_auth_headers()
    uris = {}
    for name in ("verify", "settle", "supported", "bazaar"):
        value = getattr(headers, name)["Authorization"]
        assert value.startswith("Bearer ")
        claims = pyjwt.decode(value[7:], signing_key.public_key(),
                              algorithms=["EdDSA"], options=DECODE_OPTS)
        uris[name] = claims["uris"][0]
    assert uris["verify"] == "POST api.example.com/x402/verify"
    assert uris["settle"] == "POST api.example.com/x402/settle"
    assert uris["supported"] == "GET api.example.com/x402/supported"
    # A trailing slash on the configured URL must not double up.
    assert "//verify" not in uris["verify"]


def test_a_bad_credential_fails_at_construction_not_at_first_payment(secret):
    """Startup is the cheap place to fail. The expensive place is the first
    request that has already taken a customer's money."""
    with pytest.raises(CdpAuthError):
        CdpAuthProvider(CdpCredentials(key_id=KEY_ID, secret="not base64!!"),
                        "https://h")


# -- the credential does not leak ------------------------------------------

def test_repr_does_not_print_the_secret(secret):
    """A dataclass prints its fields, and this one sits inside PaymentConfig,
    which turns up in error messages and debugger output."""
    creds = CdpCredentials(key_id=KEY_ID, secret=secret)
    assert secret not in repr(creds)
    assert "redacted" in repr(creds)
    assert KEY_ID in repr(creds)


def test_a_config_repr_does_not_print_the_secret(secret):
    from lethe_notary.payments import PaymentConfig
    config = PaymentConfig(
        pay_to="0x000000000000000000000000000000000000dEaD", price="$0.01",
        network="eip155:8453", facilitator_url="https://h",
        cdp_credentials=CdpCredentials(key_id=KEY_ID, secret=secret))
    assert secret not in repr(config)


@pytest.mark.parametrize("bad", ["not base64!!", "", base64.b64encode(b"short").decode()])
def test_a_malformed_secret_is_refused_without_echoing_it(bad):
    """The error is read off a terminal, pasted into an issue, screenshotted.
    It must be actionable without reproducing the credential."""
    with pytest.raises(CdpAuthError) as e:
        load_ed25519_key(bad)
    assert bad not in str(e.value) or bad == ""
    assert "not echoed" in str(e.value)


def test_both_key_shapes_load(signing_key, secret):
    """64 bytes is what CDP issues; 32 is what someone pastes after stripping
    the public half."""
    seed_only = base64.b64encode(signing_key.private_bytes_raw()).decode()
    for value in (secret, seed_only):
        assert (load_ed25519_key(value).private_bytes_raw()
                == signing_key.private_bytes_raw())


# -- half a credential is not a credential --------------------------------

def test_neither_variable_set_means_no_credential():
    assert CdpCredentials.from_env({}) is None


def test_both_variables_set_produces_one(secret):
    creds = CdpCredentials.from_env({"LETHE_NOTARY_CDP_KEY_ID": KEY_ID,
                                     "LETHE_NOTARY_CDP_KEY_SECRET": secret})
    assert creds is not None and creds.key_id == KEY_ID


@pytest.mark.parametrize("env,missing", [
    ({"LETHE_NOTARY_CDP_KEY_ID": KEY_ID}, "LETHE_NOTARY_CDP_KEY_SECRET"),
    ({"LETHE_NOTARY_CDP_KEY_SECRET": "x"}, "LETHE_NOTARY_CDP_KEY_ID"),
])
def test_half_a_credential_is_refused(env, missing):
    """The failure this prevents: the notary silently sends no credential at
    all, so an operator who believes they cut over to mainnet is either 401ing
    or quietly still on a keyless testnet facilitator. Exactly the shape of the
    FREE=1-beats-PAY_TO bug this package already fixed."""
    with pytest.raises(CdpAuthError) as e:
        CdpCredentials.from_env(env)
    assert missing in str(e.value)


def test_whitespace_only_counts_as_unset():
    """A trailing newline from a heredoc or a copy-paste is not a credential."""
    assert CdpCredentials.from_env({"LETHE_NOTARY_CDP_KEY_ID": "  ",
                                    "LETHE_NOTARY_CDP_KEY_SECRET": "\n"}) is None


# -- how it reaches the facilitator ----------------------------------------

@pytest.fixture
def stub_facilitator(signing_key):
    """A facilitator that answers only an authenticated caller, like CDP.

    A real HTTP server rather than a patched client, because what is being
    tested is whether the credential reaches the wire — and a stub that never
    parses a header cannot disagree with the code that builds one. It records
    what it saw so a test can assert on the Authorization header itself.
    """
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    seen: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            record: dict = {"path": self.path, "authorization": auth}
            seen.append(record)
            if not auth.startswith("Bearer "):
                record["verdict"] = "no-credential"
                return self._send(401, {"error": "unauthorized"})
            try:
                claims = pyjwt.decode(auth[7:], signing_key.public_key(),
                                      algorithms=["EdDSA"], options=DECODE_OPTS)
            except Exception as exc:
                record["verdict"] = type(exc).__name__
                return self._send(401, {"error": "bad token"})
            record["uris"] = claims["uris"]
            # The Host header verbatim, port included — which is what a real
            # facilitator has to compare against, because it is all it knows
            # about how it was addressed. Stripping the port here would have
            # hidden the `.hostname`-vs-`netloc` bug this stub caught.
            expected = f"GET {self.headers.get('Host', '')}{self.path}"
            if claims["uris"] != [expected]:
                record["verdict"] = "wrong-uri"
                return self._send(401, {"error": "token not valid here"})
            record["verdict"] = "accepted"
            self._send(200, {"kinds": [{"x402Version": 2, "scheme": "exact",
                                        "network": "eip155:8453"}]})

        def _send(self, code, body):
            raw = _json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown()


def _preflight(url, credentials):
    from lethe_notary.payments import PaymentConfig, PaymentConfigError, PaymentGate
    config = PaymentConfig(
        pay_to="0x000000000000000000000000000000000000dEaD", price="$0.01",
        network="eip155:8453", facilitator_url=url, cdp_credentials=credentials)
    try:
        PaymentGate(config).preflight()
        return True
    except PaymentConfigError:
        return False


def test_a_credential_reaches_the_facilitator_and_unlocks_mainnet(
        stub_facilitator, secret):
    """The whole point of this change. A mainnet network against a facilitator
    that demands authentication: before this code the notary could not get
    past preflight, because it sent no credential."""
    url, seen = stub_facilitator
    assert _preflight(url, CdpCredentials(key_id=KEY_ID, secret=secret)) is True
    assert [r["verdict"] for r in seen] == ["accepted"]
    assert seen[0]["uris"] == [f"GET {url.removeprefix('http://')}{seen[0]['path']}"]


def test_without_a_credential_the_notary_still_sends_no_header(stub_facilitator):
    """The default path must not change: most operators are on testnet against
    a keyless facilitator, and an unexpected Authorization header there is a
    credential sent somewhere it was never meant to go."""
    url, seen = stub_facilitator
    assert _preflight(url, None) is False
    assert [r["verdict"] for r in seen] == ["no-credential"]
    assert seen[0]["authorization"] == ""


def test_a_credential_signed_by_the_wrong_key_fails_at_boot(stub_facilitator):
    """Wrong credentials must not be discovered by a customer. Preflight runs
    before the first request, so a bad key is a startup failure."""
    url, seen = stub_facilitator
    other = ed25519.Ed25519PrivateKey.generate()
    assert _preflight(url, CdpCredentials(
        key_id=KEY_ID,
        secret=base64.b64encode(other.private_bytes_raw()).decode())) is False
    assert seen[0]["verdict"] == "InvalidSignatureError"


def test_free_mode_and_a_cdp_credential_are_refused_together(secret):
    """A credential authenticates settlement; free mode settles nothing. Same
    shape as FREE=1 beating PAY_TO: refuse rather than ignore something the
    operator provisioned on purpose."""
    from lethe_notary.payments import PaymentConfig, PaymentConfigError
    config = PaymentConfig(pay_to=None, price="$0.01", network="eip155:84532",
                           facilitator_url="https://h", free_mode=True,
                           cdp_credentials=CdpCredentials(key_id=KEY_ID, secret=secret))
    with pytest.raises(PaymentConfigError) as e:
        config.check()
    assert "LETHE_NOTARY_CDP_KEY_ID" in str(e.value)
    assert secret not in str(e.value)


@pytest.mark.parametrize("bad,expected", [
    ("!!!not base64!!!", "not valid base64"),
    (base64.b64encode(bytes(20)).decode(), "decodes to 20 bytes"),
])
def test_a_mistyped_key_is_a_config_error_not_a_facilitator_error(bad, expected):
    """Found auditing this change. The credential was parsed lazily inside
    `server()`, so a mistyped key surfaced from `preflight` wrapped in
    "facilitator X cannot settle scheme 'exact' on network Y" — sending the
    operator to hunt for a facilitator problem they do not have. It is checked
    where the payee and the network are checked, and says which variable."""
    from lethe_notary.payments import PaymentConfig
    with pytest.raises(CdpAuthError) as e:
        PaymentConfig.from_env({
            "LETHE_NOTARY_PAY_TO": "0x000000000000000000000000000000000000dEaD",
            "LETHE_NOTARY_NETWORK": "eip155:8453",
            "LETHE_NOTARY_FACILITATOR": "https://api.cdp.coinbase.com/x402",
            "LETHE_NOTARY_CDP_KEY_ID": "key-1",
            "LETHE_NOTARY_CDP_KEY_SECRET": bad,
        })
    assert expected in str(e.value)
    assert "cannot settle" not in str(e.value)
    assert bad not in str(e.value)


def test_preflight_does_not_relabel_a_credential_failure(stub_facilitator):
    """The same mislabelling, one layer down: preflight catches every
    exception and blames the facilitator. A credential error has to survive
    that unchanged, or the accurate message above gets overwritten."""
    from lethe_notary.payments import PaymentConfig, PaymentGate
    url, _ = stub_facilitator
    config = PaymentConfig(
        pay_to="0x000000000000000000000000000000000000dEaD", price="$0.01",
        network="eip155:8453", facilitator_url=url,
        cdp_credentials=CdpCredentials(key_id=KEY_ID, secret="!!!not base64!!!"))
    with pytest.raises(CdpAuthError) as e:
        PaymentGate(config).preflight()
    assert "cannot settle" not in str(e.value)


def test_tokens_stay_valid_when_minted_from_many_threads(secret, signing_key):
    """Settlement runs off the event loop in a thread pool — that is a
    deliberate design property here, since a synchronous facilitator call
    inline would serialize every other request behind it. So one shared
    Ed25519 key object gets signed with concurrently, and a token that came
    out garbled would be a 401 under load and nowhere else."""
    import concurrent.futures

    provider = CdpAuthProvider(CdpCredentials(key_id=KEY_ID, secret=secret),
                               "https://h:8443/x402")

    def mint_and_check(_):
        headers = provider.get_auth_headers()
        return all(
            pyjwt.decode(getattr(headers, name)["Authorization"][7:],
                         signing_key.public_key(), algorithms=["EdDSA"],
                         options=DECODE_OPTS)["uris"] == [f"{method} h:8443/x402{path}"]
            for name, method, path in (("verify", "POST", "/verify"),
                                       ("settle", "POST", "/settle"),
                                       ("supported", "GET", "/supported"))
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        assert all(pool.map(mint_and_check, range(200)))


def test_a_hostile_facilitator_cannot_extract_the_signing_key(secret):
    """The worst case on this path: a facilitator that reflects everything it
    receives, so whatever we sent lands in an error message the notary prints
    at boot and an operator pastes into an issue.

    A token can surface that way, and that is acceptable — it is a signature,
    not the key; it is bound to one method, host and path; it expires in two
    minutes; and the facilitator already had it. The *secret* must never
    appear, because that is forgeable forever.
    """
    import json as _json
    import threading
    import traceback
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Reflector(BaseHTTPRequestHandler):
        def do_GET(self):
            body = _json.dumps(dict(self.headers)).encode()
            self.send_response(500)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Reflector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        from lethe_notary.payments import PaymentConfig, PaymentGate
        config = PaymentConfig(
            pay_to="0x000000000000000000000000000000000000dEaD", price="$0.01",
            network="eip155:8453",
            facilitator_url=f"http://127.0.0.1:{server.server_port}",
            cdp_credentials=CdpCredentials(key_id=KEY_ID, secret=secret))
        try:
            PaymentGate(config).preflight()
            surface = ""
        except Exception as exc:
            surface = f"{exc}\n{traceback.format_exc()}"
    finally:
        server.shutdown()

    assert "Bearer" in surface, "the reflector did not echo; the test proves nothing"
    assert secret not in surface
    assert secret[:24] not in surface
