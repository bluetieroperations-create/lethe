"""External anchoring: corroborate the audit chain's state with a party the
operator does not control.

Everything else Lethe signs is self-attestation — the operator generates the
key, performs the deletion, and signs the certificate saying it happened.
`issued_at` is their own clock, so nothing structurally prevents backdating
(see docs/threat-model.md).

Anchoring the *chain head* rather than each certificate fixes that more
cheaply than timestamping every document. Once head N carries a trusted
timestamp, an entry cannot later be inserted at position N: that would change
every hash from N onward and contradict the anchor. Continuous anchoring makes
backdating a recorded forget structurally impossible, not merely detectable —
and it keeps the timestamping authority out of the deletion path, so a TSA
outage degrades anchoring instead of blocking a data-subject request.

The RFC 3161 token itself is the evidence. It is stored raw (base64) and is
verifiable by anyone with the TSA's certificate chain, using any RFC 3161
implementation — `openssl ts -verify` included. Lethe does not need to be
trusted, or even present, to check it later.
"""

import base64
import hashlib
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Protocol

try:
    from asn1crypto import algos, cms, core, tsp

    class _TimeStampResp(core.Sequence):
        """RFC 3161 s2.4.2 response.

        asn1crypto's own `tsp.TimeStampResp` marks `timeStampToken` REQUIRED,
        but the RFC makes it OPTIONAL — and a rejecting authority omits it. Its
        spec therefore cannot parse a valid rejection at all, which turned every
        refusal (rate limit, policy, malformed request) into an opaque
        "unparseable response". This spec matches the RFC so the real status
        reaches the operator.
        """

        _fields = [
            ("status", tsp.PKIStatusInfo),
            ("time_stamp_token", cms.ContentInfo, {"optional": True}),
        ]

    _ASN1_IMPORT_ERROR: str | None = None
except ImportError as exc:  # pragma: no cover - exercised by the error path below
    _ASN1_IMPORT_ERROR = str(exc)

# application/timestamp-query per RFC 3161 s3.4.
_CONTENT_TYPE = "application/timestamp-query"

# urllib speaks file://, ftp:// and more. A TSA endpoint is configuration, but
# configuration is not always trusted input, and a mistyped or injected scheme
# should never make the anchor client open a local file.
_ALLOWED_SCHEMES = ("http", "https")

# A timestamp token is a few KB. Anything vastly larger is a broken or hostile
# endpoint, and must not be read into memory unbounded.
_MAX_RESPONSE_BYTES = 1 << 20

# grantedWithMods means the TSA altered the request; the token is valid but no
# longer answers exactly what was asked. Accept only an unmodified grant.
_GRANTED = "granted"


class AnchorError(Exception):
    """Anchoring failed. Never raised for a merely unreachable TSA in a way
    that loses the head — the caller decides whether to retry."""


@dataclass(frozen=True)
class AnchorResult:
    """A third party's attestation that `digest` existed at `anchored_at`."""

    authority: str        # TSA endpoint that issued the token, credentials stripped
    token: str            # base64 of the raw RFC 3161 response — the evidence
    anchored_at: str      # the TSA's genTime, ISO-8601
    digest: str           # hex digest that was timestamped
    digest_algorithm: str
    policy: str | None    # TSA policy OID under which the token was issued


class Anchor(Protocol):
    """A source of external corroboration. Implementations must not be trusted
    by Lethe: they return evidence a third party can check independently."""

    name: str

    def anchor(self, data: bytes) -> AnchorResult:
        """Timestamp `data` and return the resulting evidence."""
        ...


class _SchemeCheckingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-apply the scheme allowlist to redirect targets.

    Validating only the configured URL leaves a gap: urllib's default redirect
    handler will follow a 3xx into ftp://, so an authority (or anything able to
    answer for it) could move the request onto a scheme the allowlist was meant
    to exclude. A TSA has no reason to redirect anywhere but http/https.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        scheme = urllib.parse.urlparse(newurl).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise AnchorError(
                f"timestamping authority redirected to a {scheme or 'schemeless'!r} "
                f"URL; only http and https are followed"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def public_authority_url(url: str) -> str:
    """The part of a TSA endpoint that is safe to publish.

    The URL is a request detail, but `authority` is evidence metadata: it is
    written into the audit chain and into the file `anchor --emit` produces for
    publication. A TSA endpoint can carry a credential — HTTP userinfo, or an
    API key in the query string — so publishing it verbatim would leak it to
    everyone the anchor is shown to. Scheme, host and path are what identify
    the authority to a verifier; the token itself carries the TSA's certificate
    anyway, so nothing verifiable is lost by dropping the rest.
    """
    parts = urllib.parse.urlsplit(url)
    # Everything after the last "@" is host[:port] — taken verbatim rather than
    # reassembled from .hostname/.port, which drops the brackets an IPv6
    # authority needs and would publish an unparseable URL.
    host = parts.netloc.rpartition("@")[2]
    return urllib.parse.urlunsplit((parts.scheme, host, parts.path, "", ""))


def _http_post(url: str, body: bytes, timeout: float) -> bytes:
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": _CONTENT_TYPE}
    )
    opener = urllib.request.build_opener(_SchemeCheckingRedirectHandler)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(body) > _MAX_RESPONSE_BYTES:
            raise AnchorError(
                f"timestamping authority returned more than {_MAX_RESPONSE_BYTES} bytes"
            )
        return body
    except urllib.error.URLError as exc:
        # Only the reason is surfaced: a raw URLError can carry the full URL,
        # and a TSA endpoint may embed a customer identifier.
        raise AnchorError(f"timestamping authority unreachable ({exc.reason})") from None


class Rfc3161Anchor:
    """RFC 3161 timestamping client.

    `transport` is injectable so the request/response handling is testable
    without a network round trip; it defaults to a stdlib POST (no `requests`
    dependency — this runs inside a compliance tool).

    NOTE ON VERIFICATION: this checks that the response answers *this* request
    — granted status, echoed nonce, and matching message imprint — which is
    what stops a substituted or replayed token being stored. It does NOT
    validate the TSA's signature chain, which needs the authority's root
    certificate and a trust decision that belongs to the verifier, not the
    issuer. Verify a stored token with, e.g.:

        openssl ts -verify -in token.tsr -data head.txt -CAfile tsa-chain.pem
    """

    name = "rfc3161"

    def __init__(
        self,
        url: str,
        *,
        hash_algorithm: str = "sha256",
        timeout: float = 20.0,
        transport=None,
    ):
        if _ASN1_IMPORT_ERROR is not None:
            raise AnchorError(
                "RFC 3161 anchoring needs asn1crypto: pip install 'lethe-delete[anchor]' "
                f"({_ASN1_IMPORT_ERROR})"
            )
        if hash_algorithm not in ("sha256", "sha384", "sha512"):
            raise AnchorError(f"unsupported hash algorithm {hash_algorithm!r}")
        scheme = urllib.parse.urlparse(url).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise AnchorError(
                f"timestamping authority URL must be http or https, got {scheme or 'none'!r}"
            )
        self.url = url
        # The request goes to `url`; only this form is ever recorded.
        self.public_url = public_authority_url(url)
        self.hash_algorithm = hash_algorithm
        self.timeout = timeout
        self._transport = transport or (
            lambda url, body: _http_post(url, body, self.timeout)
        )

    def anchor(self, data: bytes) -> AnchorResult:
        digest = hashlib.new(self.hash_algorithm, data).digest()
        # A nonce the TSA must echo. Without it a stored token could be a
        # replay of an older response for the same digest — which for a
        # timestamp is the whole attack.
        nonce = int.from_bytes(secrets.token_bytes(16), "big")

        request = tsp.TimeStampReq({
            "version": 1,
            "message_imprint": tsp.MessageImprint({
                "hash_algorithm": algos.DigestAlgorithm({"algorithm": self.hash_algorithm}),
                "hashed_message": digest,
            }),
            "nonce": core.Integer(nonce),
            # Ask for the TSA's certificates: without them the token cannot be
            # verified later except by whoever already holds the chain.
            "cert_req": True,
        })

        raw = self._transport(self.url, request.dump())
        return self._parse(raw, digest=digest, nonce=nonce)

    def _parse(self, raw: bytes, *, digest: bytes, nonce: int) -> AnchorResult:
        try:
            response = _TimeStampResp.load(raw)
            status = response["status"]["status"].native
        except Exception as exc:
            raise AnchorError(
                f"timestamping authority returned an unparseable response "
                f"({type(exc).__name__})"
            ) from None

        # Read BEFORE the token is touched: a refusal legitimately carries no
        # token, so parsing first reports "unparseable" for what is really a
        # rate limit or a policy refusal.
        if status != _GRANTED:
            raise AnchorError(f"timestamping authority refused the request (status {status!r})")

        try:
            info = response["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed
            # Every field is read inside the guard: these walk structures a
            # remote authority controls, so an unexpected shape must surface as
            # an AnchorError, never as a raw traceback out of the anchor call.
            token_nonce = info["nonce"].native
            token_imprint = info["message_imprint"]["hashed_message"].native
            anchored_at = info["gen_time"].native.isoformat()
            policy = info["policy"].native if info["policy"] else None
        except Exception as exc:
            raise AnchorError(
                f"timestamping authority granted the request but returned an "
                f"unparseable token ({type(exc).__name__})"
            ) from None

        if token_nonce != nonce:
            raise AnchorError("timestamp nonce mismatch — response is not for this request")
        if token_imprint != digest:
            raise AnchorError("timestamp imprint mismatch — token covers different data")

        return AnchorResult(
            authority=self.public_url,
            token=base64.b64encode(raw).decode(),
            anchored_at=anchored_at,
            digest=digest.hex(),
            digest_algorithm=self.hash_algorithm,
            policy=policy,
        )
