"""Contract checks for measurement parsing and scoring; no VM required."""
import unittest
from analyze import normalized_path, percentiles, quality, score, vector_mapping
from run import selected


class HarnessTests(unittest.TestCase):
    def test_rank_scoring_does_not_turn_errors_into_misses(self):
        query = {"id": "q", "query": "x", "category": "symbol", "relevant": ["a.rs"]}
        result = score(query, {"hits": {"hits": [
            {"_source": {"ax_path": "/workspace/spike/corpus/wrong.rs"}},
            {"_source": {"ax_path": "/workspace/spike/corpus/a.rs"}}]}})
        self.assertEqual(result["rank_at_5"], 2)
        self.assertEqual(quality([result])["all_positive"]["mrr_at_5"], 0.5)
        for broken in [{"error": "rejected"}, {"timed_out": True}, {"_shards": {"failed": 1}}]:
            with self.assertRaises(ValueError):
                score(query, broken)

    def test_negative_and_percentiles_are_explicit(self):
        item = score({"id": "none", "query": "absent", "category": "negative", "relevant": []}, {"hits": {"hits": []}})
        self.assertTrue(item["empty"])
        self.assertEqual(quality([item])["negative"]["empty_results"], 1)
        self.assertEqual(percentiles(list(range(1, 21)))["p95"], 19)
        with self.assertRaises(ValueError):
            percentiles([])

    def test_corpus_scope_excludes_keys_builds_and_local_settings(self):
        self.assertTrue(selected("crates/sandbox-core/src/exec.rs"))
        self.assertTrue(selected("BRD.md"))
        for path in [".env", ".cache/keys/dev-bundle.key", "target/generated.rs", ".agents/skills/a/SKILL.md"]:
            self.assertFalse(selected(path))
        self.assertEqual(normalized_path({"ax_path": "corpus/BRD.md"}), "BRD.md")
        self.assertIsNone(normalized_path({}))

    def test_nested_mapping_cannot_silently_enable_embeddings(self):
        self.assertFalse(vector_mapping({"properties": {"body": {"type": "text"}}}))
        self.assertTrue(vector_mapping({"index": {"mappings": {"properties": {"body": {"type": "semantic_text"}}}}}))


if __name__ == "__main__":
    unittest.main()
