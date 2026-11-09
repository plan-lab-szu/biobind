"""Checks for the fixed-fold scorer's leakage and protocol assumptions."""

import sys
import unittest
from collections import Counter
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from evaluate_pair_scores import choose_threshold, evaluate, load_protocol  # noqa: E402


class ProtocolTests(unittest.TestCase):
    def test_official_fold_counts(self):
        protocol = load_protocol()
        self.assertEqual(len(protocol), 6000)
        self.assertEqual(Counter(protocol.values()), Counter({(fold, label): 300
                                                       for fold in range(10)
                                                       for label in (0, 1)}))

    def test_training_threshold(self):
        self.assertEqual(choose_threshold([(1, 1), (2, 1), (3, 0), (4, 0)]), 2)
        self.assertEqual(choose_threshold([(10, 1), (11, 1), (1, 0), (2, 0)]), -1)

    def test_held_out_scores_do_not_choose_threshold(self):
        protocol = load_protocol()
        scores = {key: (1 if label else 10) for key, (_, label) in protocol.items()}
        before = evaluate(protocol, scores)["folds"][0]["threshold"]
        for key, (fold, _) in protocol.items():
            if fold == 0:
                scores[key] = 20
        after = evaluate(protocol, scores)["folds"][0]["threshold"]
        self.assertEqual(before, 1)
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
