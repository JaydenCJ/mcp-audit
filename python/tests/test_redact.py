"""Redaction policy and canonical digest tests."""

import unittest

from mcp_audit import (
    REDACTED,
    RedactionPolicy,
    canonical_json,
    digest_arguments,
    redact_arguments,
)


class RedactArgumentsTest(unittest.TestCase):
    def test_redacts_sensitive_keys_including_nested(self) -> None:
        redacted, keys = redact_arguments(
            {
                "username": "alice",
                "password": "hunter2",
                "config": {"api_key": "abc123", "retries": 3},
            }
        )
        self.assertEqual(
            redacted,
            {
                "username": "alice",
                "password": REDACTED,
                "config": {"api_key": REDACTED, "retries": 3},
            },
        )
        self.assertEqual(sorted(keys), ["config.api_key", "password"])

    def test_key_matching_ignores_case_and_separators(self) -> None:
        redacted, _ = redact_arguments(
            {
                "API-KEY": "x",
                "AccessKey": "y",
                "Authorization": "z",
                "author": "ok, not sensitive",
            }
        )
        self.assertEqual(
            redacted,
            {
                "API-KEY": REDACTED,
                "AccessKey": REDACTED,
                "Authorization": REDACTED,
                "author": "ok, not sensitive",
            },
        )

    def test_redacts_secret_shaped_values_under_innocent_keys(self) -> None:
        redacted, keys = redact_arguments(
            {
                "note": "sk-abcdefghijklmnopqrstuvwxyz123456",
                "header": "Bearer abc.def.ghi",
                "aws": ["AKIAIOSFODNN7EXAMPLE is the key"],
                "plain": "hello world",
            }
        )
        self.assertEqual(
            redacted,
            {
                "note": REDACTED,
                "header": REDACTED,
                "aws": [REDACTED],
                "plain": "hello world",
            },
        )
        self.assertIn("aws[0]", keys)

    def test_custom_keys(self) -> None:
        redacted, _ = redact_arguments(
            {"internal_id": "42", "code_name": "blue-falcon"},
            RedactionPolicy(extra_sensitive_keys=["codename"]),
        )
        self.assertEqual(redacted, {"internal_id": "42", "code_name": REDACTED})

    def test_none_arguments(self) -> None:
        self.assertEqual(redact_arguments(None), (None, []))

    def test_invalid_mode_rejected(self) -> None:
        with self.assertRaises(ValueError):
            RedactionPolicy(mode="everything")


class CanonicalJsonTest(unittest.TestCase):
    def test_sorts_keys_recursively_and_strips_whitespace(self) -> None:
        value = {"b": 1, "a": {"z": True, "y": [2, {"d": 1, "c": 0}]}}
        self.assertEqual(canonical_json(value), '{"a":{"y":[2,{"c":0,"d":1}],"z":true},"b":1}')

    def test_pinned_cross_language_digest_vector(self) -> None:
        # The same vector is asserted in ts/tests/redact.test.ts; both SDKs
        # must agree byte-for-byte on the canonical encoding.
        digest = digest_arguments({"order_id": "42", "api_key": "sk-abcdefghijklmnopqrstuvwx"})
        self.assertEqual(digest["byte_length"], 57)
        self.assertEqual(
            digest["sha256"],
            "9edc1256cf72675158f929c4db1d7fc635892123a6fb91d12cf74b42742616de",
        )

    def test_digest_covers_original_value(self) -> None:
        args = {"token": "secret-token-value"}
        redacted, keys = redact_arguments(args)
        digest = digest_arguments(args, keys)
        self.assertEqual(redacted, {"token": REDACTED})
        self.assertEqual(digest["sha256"], digest_arguments({"token": "secret-token-value"})["sha256"])
        self.assertNotEqual(digest["sha256"], digest_arguments({"token": REDACTED})["sha256"])
        self.assertEqual(digest["redacted_keys"], ["token"])


if __name__ == "__main__":
    unittest.main()
