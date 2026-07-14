"""W3C Trace Context helper tests."""

import unittest

from mcp_audit import (
    child_traceparent,
    generate_traceparent,
    is_valid_traceparent,
    parse_traceparent,
)

SAMPLE = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


class ParseTraceparentTest(unittest.TestCase):
    def test_parses_valid_header(self) -> None:
        ctx = parse_traceparent(SAMPLE)
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.trace_id, "0af7651916cd43dd8448eb211c80319c")
        self.assertEqual(ctx.span_id, "b7ad6b7169203331")
        self.assertEqual(ctx.flags, "01")

    def test_rejects_malformed_values(self) -> None:
        self.assertIsNone(parse_traceparent("not-a-traceparent"))
        self.assertIsNone(parse_traceparent(""))
        self.assertIsNone(
            parse_traceparent("01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
        )
        self.assertIsNone(
            parse_traceparent("00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01")
        )

    def test_rejects_all_zero_ids(self) -> None:
        self.assertIsNone(parse_traceparent(f"00-{'0' * 32}-b7ad6b7169203331-01"))
        self.assertIsNone(parse_traceparent(f"00-0af7651916cd43dd8448eb211c80319c-{'0' * 16}-01"))


class GenerateTraceparentTest(unittest.TestCase):
    def test_generates_valid_unique_values(self) -> None:
        first = generate_traceparent()
        second = generate_traceparent()
        self.assertTrue(is_valid_traceparent(first))
        self.assertTrue(is_valid_traceparent(second))
        self.assertNotEqual(first, second)

    def test_child_keeps_trace_id_and_flags(self) -> None:
        child = child_traceparent(SAMPLE)
        ctx = parse_traceparent(child)
        self.assertEqual(ctx.trace_id, "0af7651916cd43dd8448eb211c80319c")
        self.assertEqual(ctx.flags, "01")
        self.assertNotEqual(ctx.span_id, "b7ad6b7169203331")

    def test_child_falls_back_for_malformed_parent(self) -> None:
        self.assertTrue(is_valid_traceparent(child_traceparent("garbage")))


if __name__ == "__main__":
    unittest.main()
