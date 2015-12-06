#!/usr/bin/env python
from git_cat_index import parse
import unittest


class TestGitCatIndex(unittest.TestCase):
    def test_an_empty_file(self):
        msgs = parse("testdata/an-empty-file")
        expected = [
            "DIRC (dircache), 1 entries",
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 (stage:0) readme.txt"
        ]
        for i in range(len(expected)):
            self.assertEqual(expected[i], msgs[i])

    def test_after_commit(self):
        msgs = parse("testdata/after-commit")
        expected = [
            "DIRC (dircache), 1 entries",
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 (stage:0) readme.txt",
            "TREE",
            "7737016481fd9dbdf0ec0d9145d56358fd71feb2 (0/1) "
        ]
        for i in range(len(expected)):
            self.assertEqual(expected[i], msgs[i])

    def test_invalidated_tree(self):
        msgs = parse("testdata/invalidated-tree")
        expected = [
            "DIRC (dircache), 2 entries",
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 (stage:0) a",
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 (stage:0) b",
            "TREE",
            "invalidated (0/-1) "
        ]
        for i in range(len(expected)):
            self.assertEqual(expected[i], msgs[i])

    def test_conflict(self):
        msgs = parse("testdata/conflict")
        expected = [
            "DIRC (dircache), 3 entries",
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 (stage:1) readme.txt",
            "72943a16fb2c8f38f9dde202b7a70ccc19c52f34 (stage:2) readme.txt",
            "f761ec192d9f0dca3329044b96ebdb12839dbff6 (stage:3) readme.txt"
        ]
        for i in range(len(expected)):
            self.assertEqual(expected[i], msgs[i])

    def test_resolve(self):
        msgs = parse("testdata/resolve")
        expected = [
            "DIRC (dircache), 1 entries",
            "f761ec192d9f0dca3329044b96ebdb12839dbff6 (stage:0) readme.txt",
            "REUC",
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 (stage:1) "
            "100644 readme.txt",
            "72943a16fb2c8f38f9dde202b7a70ccc19c52f34 (stage:2) "
            "100644 readme.txt",
            "f761ec192d9f0dca3329044b96ebdb12839dbff6 (stage:3) "
            "100644 readme.txt"
        ]
        for i in range(len(expected)):
            self.assertEqual(expected[i], msgs[i])

    def test_reuc_missing_stage(self):
        msgs = parse("testdata/reuc-missing-stage")
        expected = [
            "DIRC (dircache), 1 entries",
            "0f0e04a55cae4cb726cc89a3c3b13203836b4ed7 (stage:0) readme.txt",
            "REUC",
            "                                         (stage:1) "
            "     0 readme.txt",
            "d6459e005434a49a66a3ddec92279a86160ad71f (stage:2) "
            "100644 readme.txt",
            "72943a16fb2c8f38f9dde202b7a70ccc19c52f34 (stage:3) "
            "100644 readme.txt"
        ]
        for i in range(len(expected)):
            self.assertEqual(expected[i], msgs[i])


if __name__ == '__main__':
    unittest.main()
