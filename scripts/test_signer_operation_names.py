"""The operation boundary scans the whole frozen catalog and unknown selectors."""
import json
import tempfile
import unittest
from pathlib import Path

from check_signer_operation_names import CATALOG, DOMAINS, ROOT, selector_comparisons, violations


class OperationBoundaryTests(unittest.TestCase):
    def test_all_eighty_rows_supply_the_scan_including_unserved_names(self):
        rows = json.loads((ROOT / "docs/vectors/human-assurance-v1.json").read_text())["operations"]
        self.assertEqual(len(rows), 80)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vector = root / "docs/vectors/human-assurance-v1.json"
            vector.parent.mkdir(parents=True)
            vector.write_text(json.dumps({"operations": rows}))
            for domain in DOMAINS:
                (root / domain).mkdir(parents=True)
            (root / CATALOG).write_text('_ROWS = ({"operation": "team.agent.renew", "variant": "default"},)\n')
            # An adapter has no exemption; generated data and tests are outside
            # these explicit production directories.
            adapter = root / DOMAINS[1] / "adapter.py"
            adapter.write_text('name = "team.agent.renew"\n')
            errors = violations(root)
            self.assertEqual(len(errors), 1)
            self.assertIn("adapter.py:1: team.agent.renew", errors[0])

    def test_unserved_python_selectors_are_detected_without_a_name_list(self):
        for code in (
            'if operation.operation == "team.log-key.sign": pass',
            'if intent["operation"] == "no.contract.row": pass',
            'if intent.get("operation") == "no.contract.row": pass',
            'if operation.variant != "another": pass',
            'if operation.spec.family == "some_family": pass',
            'if operation.spec.effect.provider == "some_provider": pass',
            'if provider in {"some_provider"}: pass',
            'if "another" == variant: pass',
            'if operation not in {"no.contract.row"}: pass',
            'match operation.operation:\n    case "no.contract.row": pass',
        ):
            with self.subTest(code=code):
                self.assertEqual(selector_comparisons(code, ".py"), [1])

    def test_script_selectors_are_detected_in_both_directions(self):
        for code in (
            'if (intent.operation === "no.contract.row") {}',
            'if (intent["variant"] !== "anything") {}',
            'if ("no.contract.row" === intent.operation) {}',
            'if (row.family === "some_family") {}',
            'if (effect.provider !== "some_provider") {}',
        ):
            with self.subTest(code=code):
                self.assertEqual(selector_comparisons(code, ".js"), [1])

    def test_catalog_cannot_export_an_operation_name_as_a_scalar(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vector = root / "docs/vectors/human-assurance-v1.json"
            vector.parent.mkdir(parents=True)
            vector.write_bytes((ROOT / "docs/vectors/human-assurance-v1.json").read_bytes())
            for domain in DOMAINS:
                (root / domain).mkdir(parents=True)
            (root / CATALOG).write_text('REVOKE_OPERATION = "human-role.revoke"\n')
            errors = violations(root)
            self.assertEqual(len(errors), 1)
            self.assertIn("catalog.py:1: exported operation-name string", errors[0])

    def test_nonselector_fields_and_data_driven_comparisons_are_not_dispatch(self):
        for code in (
            'if actor.principal != subject["root_id"]: pass',
            'if purpose == "prepare": pass',
            'if operation.context != actor.context: pass',
            'if intent["operation"] != definition.operation: pass',
        ):
            self.assertEqual(selector_comparisons(code, ".py"), [])

    def test_current_production_tree_uses_only_catalog_names(self):
        self.assertEqual(violations(), [])


if __name__ == "__main__":
    unittest.main()
