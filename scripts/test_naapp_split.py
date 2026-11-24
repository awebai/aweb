"""The cutover's path list and the check that a merge from main keeps it."""

import unittest

from naapp_split import Paths, check


def paths(**overrides):
    fields = {
        "deleted_prefixes": ("naapp/", "naapp-lib/"),
        "deleted": ("naapp/folio/app.py", "naapp-lib/src/aweb_naapp/chrome.py"),
        "moved": {"naapp-lib/src/aweb_naapp/manifest.py": "naapp-contracts/src/aweb_naapp_contracts/manifest.py"},
    }
    fields.update(overrides)
    return Paths(**fields)


BASE = (
    "server/app.py",
    "naapp/folio/app.py",
    "naapp-lib/src/aweb_naapp/chrome.py",
    "naapp-lib/src/aweb_naapp/manifest.py",
)
HEAD = ("server/app.py", "naapp-contracts/src/aweb_naapp_contracts/manifest.py")


class Check(unittest.TestCase):
    def test_a_tree_that_keeps_the_list_passes(self):
        self.assertEqual(check(paths(), base=BASE, head=HEAD), [])

    def test_a_file_main_added_under_a_deleted_prefix_fails_until_listed(self):
        base = BASE + ("naapp-lib/src/aweb_naapp/hooks/new_contract.py",)
        self.assertEqual(
            check(paths(), base=base, head=HEAD),
            ["unlisted: naapp-lib/src/aweb_naapp/hooks/new_contract.py is under a deleted prefix"],
        )

    def test_a_listed_deletion_still_present_fails(self):
        self.assertEqual(
            check(paths(), base=BASE, head=HEAD + ("naapp/folio/app.py",)),
            ["not deleted: naapp/folio/app.py"],
        )

    def test_a_move_whose_source_returned_fails(self):
        head = HEAD + ("naapp-lib/src/aweb_naapp/manifest.py",)
        self.assertEqual(
            check(paths(), base=BASE, head=head),
            ["not moved: naapp-lib/src/aweb_naapp/manifest.py is still present"],
        )

    def test_a_move_whose_target_is_missing_fails(self):
        self.assertEqual(
            check(paths(), base=BASE, head=("server/app.py",)),
            ["not moved: naapp-contracts/src/aweb_naapp_contracts/manifest.py is missing"],
        )

    def test_a_file_outside_the_prefixes_is_the_branchs_own_business(self):
        self.assertEqual(check(paths(), base=BASE + ("docs/new.md",), head=HEAD), [])

    def test_a_listed_path_main_removed_is_reported_for_regeneration(self):
        base = tuple(path for path in BASE if path != "naapp/folio/app.py")
        self.assertEqual(
            check(paths(), base=base, head=HEAD),
            ["stale: naapp/folio/app.py is listed but main no longer has it"],
        )


if __name__ == "__main__":
    unittest.main()
