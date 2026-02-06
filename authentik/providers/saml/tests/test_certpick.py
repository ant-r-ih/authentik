from __future__ import annotations

from base64 import b64encode
from datetime import UTC, datetime, timedelta
from unittest import TestCase

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

# Import your function under test
from authentik.providers.saml.processors.import_sp import pick_preferred_x509_b64


def _make_cert_der(*, not_before: datetime, not_after: datetime) -> bytes:
    """
    Build a self-signed X.509 certificate as DER bytes.

    The certificate is only used for validity window testing, so subject/issuer
    content is minimal and the key is ephemeral.
    """
    if not_before.tzinfo is None or not_after.tzinfo is None:
        raise ValueError("not_before/not_after must be timezone-aware")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    return cert.public_bytes(Encoding.DER)


def _der_to_b64(der: bytes) -> str:
    # Base64 string without PEM headers, same shape as ds:X509Certificate contents.
    return b64encode(der).decode("ascii")


class TestPickPreferredX509(TestCase):
    def test_picks_currently_valid_cert(self):
        now = datetime(2026, 2, 10, 12, 0, 0, tzinfo=UTC)

        # cert_a: expired
        der_a = _make_cert_der(
            not_before=now - timedelta(days=10),
            not_after=now - timedelta(days=1),
        )
        # cert_b: valid now
        der_b = _make_cert_der(
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=10),
        )
        # cert_c: not yet valid
        der_c = _make_cert_der(
            not_before=now + timedelta(days=1),
            not_after=now + timedelta(days=20),
        )

        certs = [_der_to_b64(der_a), _der_to_b64(der_b), _der_to_b64(der_c)]

        chosen = pick_preferred_x509_b64(certs, now=now)
        self.assertEqual(chosen[0], certs[1])

    def test_falls_back_to_first_when_none_valid(self):
        now = datetime(2026, 2, 10, 12, 0, 0, tzinfo=UTC)

        # cert_a: expired
        der_a = _make_cert_der(
            not_before=now - timedelta(days=10),
            not_after=now - timedelta(days=5),
        )
        # cert_b: not yet valid
        der_b = _make_cert_der(
            not_before=now + timedelta(days=1),
            not_after=now + timedelta(days=10),
        )

        certs = [_der_to_b64(der_a), _der_to_b64(der_b)]

        chosen = pick_preferred_x509_b64(certs, now=now)
        self.assertEqual(chosen[0], certs[0])

    def test_skips_unparseable_entries(self):
        now = datetime(2026, 2, 10, 12, 0, 0, tzinfo=UTC)

        der_valid = _make_cert_der(
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=1),
        )

        certs = [
            "this-is-not-base64!!!",
            _der_to_b64(der_valid),
        ]

        chosen = pick_preferred_x509_b64(certs, now=now)
        self.assertEqual(chosen[0], certs[1])

    def test_empty_list_returns_none(self):
        chosen = pick_preferred_x509_b64([], now=datetime.now(UTC))
        self.assertListEqual(chosen, [])
