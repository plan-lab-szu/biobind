"""Bounded abstract state exploration, not a Solidity or cryptographic verification."""
import argparse
import itertools
import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

# Session=(phase, snapshot, captured, unique, duplicate_at_prewrite).
# phase: 0 unopened, 1 opened, 2 captured, 3 verdict, 4 finalized, 5 issued, 6 aborted/duplicate.
EMPTY = (0, (), -1, False, False)

def explore(persons, removed=None):
    start = ((), (), (EMPTY,) * len(persons), ())  # ideal gallery, real gallery, sessions, credentials
    queue = deque([start]); parent = {start: None}; transitions = 0
    def trace(state, action):
        actions = [action]
        while parent[state] is not None:
            state, step = parent[state]; actions.append(step)
        return actions[::-1]
    while queue:
        state = queue.popleft()
        ideal, real, sessions, credentials = state
        for i, sess in enumerate(sessions):
            phase, snapshot, captured, unique, dup_pre = sess
            choices = []
            if phase == 0:
                choices.append(("open", (1, real, -1, False, False), ideal, real, credentials))
            elif phase == 1:
                choices.append(("capture", (2, snapshot, persons[i], False, False), ideal, real, credentials))
            elif phase == 2:
                verdicts = {captured not in snapshot}
                if removed == "I4": verdicts.add(True)
                for verdict in verdicts:
                    choices.append((f"verdict={verdict}", (3, snapshot, captured, verdict, False), ideal, real, credentials))
            elif phase == 3:
                if not unique:
                    choices.append(("duplicate", (6, snapshot, captured, unique, False), ideal, real, credentials))
                elif removed != "I3" and len(snapshot) != len(ideal):
                    choices.append(("stale-abort", (6, snapshot, captured, unique, False), ideal, real, credentials))
                else:
                    for drop in ([False, True] if removed == "I2" else [False]):
                        choices.append(("finalize/drop" if drop else "finalize/write",
                                        (4, snapshot, captured, True, captured in ideal),
                                        ideal + (captured,), real + ((-1 if drop else captured),), credentials))
            elif phase == 4:
                for committed in ([captured, 1-captured] if removed == "I1" else [captured]):
                    choices.append((f"issue/vector={committed}", (5, snapshot, captured, unique, dup_pre),
                                    ideal, real, credentials+((i,committed),)))
            for action, new_sess, new_ideal, new_real, new_creds in choices:
                transitions += 1
                new_sessions = sessions[:i] + (new_sess,) + sessions[i+1:]
                new_state = (new_ideal, new_real, new_sessions, new_creds)
                failures = []
                if any(v != new_sessions[s][2] for s,v in new_creds): failures.append("W1")
                if new_ideal != new_real: failures.append("W2")
                if any(new_sessions[s][4] for s,v in new_creds): failures.append("W3")
                # Each receipt is consumed at most once; all traces exhaust every enabled issuance.
                assert len({s for s,v in new_creds}) == len(new_creds)
                if failures:
                    return {"states": len(parent), "transitions": transitions, "failures": failures,
                            "counterexample": trace(state, f"s{i}:{action}"), "persons": persons}
                if new_state not in parent:
                    parent[new_state] = (state, f"s{i}:{action}"); queue.append(new_state)
    return {"states": len(parent), "transitions": transitions, "failures": [], "persons": persons}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    assert not args.out.exists(), "preserve prior run"
    secure = [explore(p) for p in itertools.product(range(2), repeat=3)]
    ablations = {}
    for condition in ["I1", "I2", "I3", "I4"]:
        for persons in itertools.product(range(2), repeat=3):
            result = explore(persons, condition)
            if result["failures"]:
                ablations[condition] = result; break
    assert all(not r["failures"] for r in secure)
    assert len(ablations) == 4
    report = {"generatedAt": datetime.now(timezone.utc).isoformat(), "sessions": 3, "people": 2,
              "secure": secure, "ablations": ablations,
              "totalSecureStates": sum(r["states"] for r in secure),
              "totalSecureTransitions": sum(r["transitions"] for r in secure),
              "scope": "Finite abstract model, exact-equality duplicate relation, perfect primitive/backend assumptions. Not bytecode verification, person-level accuracy, or an unbounded proof.",
              "I3Ablation": "Abstract variant writes a fresh slot at finalization while preserving the captured vector. It models trusted slot re-encoding, NOT removal of one check in the fixed-slot Solidity implementation.",
              "W3Timing": "Gallery immediately before the session's atomic insertion; the session's own newly inserted vector is excluded."}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"secureStates": report["totalSecureStates"], "secureTransitions": report["totalSecureTransitions"],
                      "secureFailures": 0, "ablationCounterexamples": {k:v["failures"] for k,v in ablations.items()}}))

if __name__ == "__main__": main()
