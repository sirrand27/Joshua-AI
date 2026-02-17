#!/usr/bin/env python3
"""
W.O.P.R. Phase 5 Verification Tests
=====================================
Validates forensic investigation chains, device resolution,
chain template matching, and anti-hallucination defenses.

Usage:
    python test_forensics.py              # Run all tests
    python test_forensics.py -v           # Verbose output
"""

import json
import os
import re
import sys
import unittest

# Ensure project dir is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestExtractDeviceName(unittest.TestCase):
    """Test _extract_device_name() query parsing."""

    def setUp(self):
        from agent import _extract_device_name
        self.extract = _extract_device_name

    def test_mac_address(self):
        result = self.extract("investigate 3c:dc:75:5a:77:d4")
        self.assertEqual(result, "3c:dc:75:5a:77:d4")

    def test_ip_address(self):
        result = self.extract("check 192.168.100.89")
        self.assertEqual(result, "192.168.100.89")

    def test_hostname_investigate(self):
        result = self.extract("investigate WOPR2024")
        self.assertIn("wopr2024", result.lower())

    def test_hostname_possessive(self):
        result = self.extract("investigate Xavier's PC")
        self.assertIn("xavier", result.lower())

    def test_what_is_doing(self):
        result = self.extract("what is SmartHub doing")
        self.assertIn("smarthub", result.lower())

    def test_timeline_for(self):
        result = self.extract("timeline for esp32s3-D901BC")
        self.assertIn("esp32s3", result.lower())

    def test_lateral_movement(self):
        result = self.extract("lateral movement from 192.168.100.109")
        self.assertEqual(result, "192.168.100.109")

    def test_action_verbs_not_extracted(self):
        """Action verbs should not be treated as device names."""
        result = self.extract("investigate who is attacking from the router")
        self.assertNotEqual(result, "attacking")
        self.assertNotEqual(result, "router")  # "router" is > 3 chars and not in skip

    def test_network_terms_not_extracted(self):
        """Network terms should be in skip list."""
        result = self.extract("what is the network status")
        self.assertNotEqual(result, "status")
        self.assertNotEqual(result, "network")


class TestChainTemplateMatching(unittest.TestCase):
    """Test _get_chain_template() query routing."""

    def setUp(self):
        from agent import InboxHandler
        # Create a minimal handler for testing
        self.handler = InboxHandler.__new__(InboxHandler)

    def test_device_investigation(self):
        result = self.handler._get_chain_template("investigate WOPR2024")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "device_investigation")

    def test_forensic_timeline(self):
        result = self.handler._get_chain_template("timeline for SmartHub")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "forensic_timeline")

    def test_lateral_movement(self):
        result = self.handler._get_chain_template("check lateral movement from 192.168.100.109")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "lateral_movement_check")

    def test_incident_response(self):
        result = self.handler._get_chain_template("incident response for SmartHub")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "incident_response")

    def test_network_overview(self):
        result = self.handler._get_chain_template("give me a network overview")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "network_overview")

    def test_no_false_positive_health(self):
        """'what is the network health' should NOT trigger device_investigation."""
        result = self.handler._get_chain_template("what is the network health")
        # Should be None (no chain) because network_terms guard blocks it
        if result is not None:
            self.assertNotEqual(result[0], "device_investigation")

    def test_no_false_positive_status(self):
        """'check network status' should NOT trigger device_investigation."""
        result = self.handler._get_chain_template("check network status")
        if result is not None:
            self.assertNotEqual(result[0], "device_investigation")

    def test_no_false_positive_overview(self):
        """'what is the fleet summary' should NOT trigger device_investigation."""
        result = self.handler._get_chain_template("what is the fleet summary")
        if result is not None:
            self.assertNotEqual(result[0], "device_investigation")


class TestDeviceDBQuery(unittest.TestCase):
    """Test device_db_query tool with real DB data."""

    def test_lookup_by_hostname(self):
        from tools import device_db_query
        result = device_db_query("lookup", name="SmartHub")
        data = json.loads(result)
        self.assertIsInstance(data, list)
        if data:  # May be empty if DB doesn't have this device
            self.assertIn("mac", data[0])

    def test_lookup_by_mac(self):
        from tools import device_db_query
        result = device_db_query("lookup", name="fc:01:2c:d9:01:bc")
        data = json.loads(result)
        self.assertIsInstance(data, list)

    def test_lookup_by_ip(self):
        from tools import device_db_query
        result = device_db_query("lookup", name="192.168.100.109")
        data = json.loads(result)
        self.assertIsInstance(data, list)

    def test_timeline(self):
        from tools import device_db_query
        result = device_db_query("timeline", mac="fc:01:2c:d9:01:bc", hours=24)
        data = json.loads(result)
        self.assertIn("device", data)
        self.assertIn("events", data)

    def test_correlate(self):
        from tools import device_db_query
        result = device_db_query("correlate", mac="fc:01:2c:d9:01:bc", window_minutes=30)
        data = json.loads(result)
        self.assertIn("mac", data)
        self.assertIn("correlated_devices", data)

    def test_anomalies(self):
        from tools import device_db_query
        result = device_db_query("anomalies", mac="fc:01:2c:d9:01:bc", days=7)
        data = json.loads(result)
        self.assertIn("device_summary", data)
        self.assertIn("response_actions", data)

    def test_missing_params(self):
        from tools import device_db_query
        result = device_db_query("lookup")
        data = json.loads(result)
        self.assertIn("error", data)

    def test_invalid_query_type(self):
        from tools import device_db_query
        result = device_db_query("invalid_type")
        data = json.loads(result)
        self.assertIn("error", data)


class TestMACValidation(unittest.TestCase):
    """Test MAC heuristic in device_db.py get_device_by_name."""

    def test_hostname_with_dash_not_mac(self):
        """Hostnames like 'RawiNet-IoT' should NOT trigger MAC branch."""
        from device_db import DeviceKnowledgeBase
        db = DeviceKnowledgeBase()
        # This should go through hostname search, not MAC search
        result = db.get_device_by_name("RawiNet-IoT")
        # No crash, returns list (possibly empty)
        self.assertIsInstance(result, list)

    def test_partial_mac_accepted(self):
        """Partial MAC like 'fc:01:2c' should trigger MAC search."""
        from device_db import DeviceKnowledgeBase
        db = DeviceKnowledgeBase()
        result = db.get_device_by_name("fc:01:2c")
        self.assertIsInstance(result, list)

    def test_full_mac_accepted(self):
        """Full MAC should trigger MAC search."""
        from device_db import DeviceKnowledgeBase
        db = DeviceKnowledgeBase()
        result = db.get_device_by_name("fc:01:2c:d9:01:bc")
        self.assertIsInstance(result, list)


class TestTrainingData(unittest.TestCase):
    """Validate training data quality."""

    def test_all_valid_json(self):
        path = os.path.join(os.path.dirname(__file__),
                           "training_data/wopr_cybersec_curated.jsonl")
        if not os.path.exists(path):
            self.skipTest("Training data not found")

        count = 0
        with open(path) as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    self.fail(f"Invalid JSON at line {i}")
                self.assertIn("messages", data, f"Missing 'messages' at line {i}")
                msgs = data["messages"]
                roles = [m["role"] for m in msgs]
                self.assertEqual(roles, ["system", "user", "assistant"],
                               f"Bad roles at line {i}: {roles}")
                count += 1

        self.assertGreaterEqual(count, 360, f"Expected >= 360 examples, got {count}")

    def test_signoff_consistency(self):
        path = os.path.join(os.path.dirname(__file__),
                           "training_data/wopr_cybersec_curated.jsonl")
        if not os.path.exists(path):
            self.skipTest("Training data not found")

        missing = 0
        with open(path) as f:
            for line in f:
                data = json.loads(line.strip())
                asst = data["messages"][2]["content"]
                if "W.O.P.R. out" not in asst:
                    missing += 1

        self.assertEqual(missing, 0, f"{missing} examples missing W.O.P.R. signoff")


class TestRoleBoundaryData(unittest.TestCase):
    """Validate role boundary and anti-hallucination training data."""

    def setUp(self):
        self.path = os.path.join(os.path.dirname(__file__),
                                 "training_data/wopr_cybersec_curated.jsonl")
        if not os.path.exists(self.path):
            self.skipTest("Training data not found")
        with open(self.path) as f:
            self.examples = [json.loads(line.strip()) for line in f if line.strip()]

    def test_scope_refusal_examples_exist(self):
        """At least 10 examples should contain scope refusal language."""
        refusal_count = 0
        for ex in self.examples:
            asst = ex["messages"][2]["content"]
            if "outside my operational scope" in asst.lower() or \
               "outside w.o.p.r. operational scope" in asst.lower():
                refusal_count += 1
        self.assertGreaterEqual(refusal_count, 10,
                                f"Only {refusal_count} scope refusal examples (need >= 10)")

    def test_deferral_agents_mentioned(self):
        """Scope refusals should mention TARS Dev, JOSHUA, or operator."""
        for ex in self.examples:
            asst = ex["messages"][2]["content"]
            # Only check examples where scope refusal is the primary response
            # (starts with "That is outside" — not embedded in longer analysis)
            if asst.strip().startswith("That is outside my operational scope"):
                has_deferral = any(d in asst for d in ["TARS Dev", "JOSHUA", "operator"])
                self.assertTrue(has_deferral,
                                f"Scope refusal without deferral agent: {asst[:80]}")

    def test_no_real_ips_in_new_categories(self):
        """New categories (examples 250+) should not contain 192.168.100.x IPs."""
        for i, ex in enumerate(self.examples[250:], start=251):
            for msg in ex["messages"]:
                content = msg["content"]
                matches = re.findall(r'192\.168\.100\.\d+', content)
                self.assertEqual(len(matches), 0,
                                 f"Real IP found in example {i}: {matches}")

    def test_anti_hallucination_phrases(self):
        """Training data should contain anti-hallucination language."""
        halluc_phrases = [
            "cannot fabricate", "will not fabricate", "do not fabricate",
            "insufficient data", "do not speculate", "do not make predictions",
            "cannot confirm", "sensor limitation",
        ]
        found = set()
        for ex in self.examples:
            asst = ex["messages"][2]["content"].lower()
            for phrase in halluc_phrases:
                if phrase in asst:
                    found.add(phrase)
        self.assertGreaterEqual(len(found), 4,
                                f"Only {len(found)} anti-hallucination phrases found: {found}")

    def test_mining_fleet_examples_exist(self):
        """At least 10 examples should reference mining fleet concepts."""
        mining_keywords = ["axeos", "nerdminer", "cgminer", "hashrate",
                          "stratum", "mining fleet", "bitaxe"]
        mining_count = 0
        for ex in self.examples:
            content = ex["messages"][2]["content"].lower()
            if any(kw in content for kw in mining_keywords):
                mining_count += 1
        self.assertGreaterEqual(mining_count, 10,
                                f"Only {mining_count} mining examples (need >= 10)")


class TestPipelineStatus(unittest.TestCase):
    """Verify fine-tuning pipeline readiness."""

    def test_curated_dataset_exists(self):
        path = os.path.join(os.path.dirname(__file__),
                           "training_data/wopr_cybersec_curated.jsonl")
        self.assertTrue(os.path.exists(path))

    def test_finetune_script_exists(self):
        path = os.path.join(os.path.dirname(__file__), "finetune_wopr.py")
        self.assertTrue(os.path.exists(path))

    def test_device_db_exists(self):
        path = os.path.join(os.path.dirname(__file__), "wopr_devices.db")
        self.assertTrue(os.path.exists(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
