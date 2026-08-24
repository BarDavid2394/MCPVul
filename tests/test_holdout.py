import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "evaluation" / "scripts"
sys.path.insert(0, str(SCRIPTS))


def load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


holdout_common = load_module("holdout_common")


class HoldoutTests(unittest.TestCase):
    def manifest(self):
        return {
            "schema_version": 1,
            "state": "staging",
            "sources": [{
                "id": "source", "kind": "git", "url": "https://example.invalid/repo.git",
                "revision": "a" * 40,
            }],
            "artifacts": [{"id": "artifact", "source_id": "source", "path": "server.py"}],
            "labels": [{
                "artifact_id": "artifact", "rule_id": "MCP05-COMMAND-INJECTION",
                "polarity": "positive", "provenance": "reviewed-advisory",
            }],
        }

    def test_staging_manifest_validation(self):
        self.assertEqual([], holdout_common.validate(self.manifest()))

    def test_frozen_manifest_requires_artifact_hash(self):
        data = self.manifest()
        data["state"] = "frozen"
        errors = holdout_common.validate(data, frozen=True)
        self.assertTrue(any("requires sha256" in error for error in errors))

    def test_unknown_is_not_implicitly_negative(self):
        data = self.manifest()
        self.assertEqual(1, len(data["labels"]))
        self.assertNotIn(("artifact", "MCP13-SSRF"), {
            (label["artifact_id"], label["rule_id"]) for label in data["labels"]
        })

    def test_fingerprint_is_stable_across_key_order(self):
        data = self.manifest()
        reordered = json.loads(json.dumps(data, sort_keys=True))
        self.assertEqual(holdout_common.fingerprint(data), holdout_common.fingerprint(reordered))

    def test_token_is_bound_to_manifest(self):
        run_holdout = load_module("run_holdout")
        token = "one-time"
        self.assertNotEqual(
            run_holdout.token_digest(token, "a" * 64),
            run_holdout.token_digest(token, "b" * 64),
        )


if __name__ == "__main__":
    unittest.main()
