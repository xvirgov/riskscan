"""Engine regression tests. Zero-dependency: run with `python3 tests/test_engine.py`
(or `pytest`). Guards the scoring bands and the false-positive fixes."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from riskscan import engine  # noqa: E402

BUILTIN_ONLY = {"analyzers": {"builtin": {"enabled": True}}, "on_missing": "suggest"}


def score(cmd):
    r = engine.analyze(engine.make_action("command", command=cmd), BUILTIN_ONLY)
    return r["overall"]


def top_label(cmd):
    r = engine.analyze(engine.make_action("command", command=cmd), BUILTIN_ONLY)
    return sorted(r["findings"], key=lambda x: -x[1])[0][2] if r["findings"] else ""


def test_recursive_flag_is_not_rm():
    # regression: `--recursive` on a non-rm command must not read as a recursive delete
    for cmd in ["cp --recursive a b", "wget --recursive http://x", "ls --recursive",
                "aws s3 sync a b --recursive", "grep --recursive p ."]:
        assert score(cmd) <= 2, cmd
        assert "force-delete" not in top_label(cmd), cmd


def test_real_rm_still_flagged():
    assert score("rm -rf ~/") == 10
    assert score("rm -rf /") == 10
    assert score("rm --recursive --force ./build") == 7
    assert score("rm -r ./build") == 7


def test_comparison_gt_is_not_a_redirect():
    # regression: `>` inside arithmetic / test / process-substitution is not a file overwrite
    for cmd in ["echo $((3 > 2))", "[[ $a > $b ]]", "diff <(sort a) <(sort b)"]:
        assert score(cmd) <= 2, cmd


def test_real_redirect_still_flagged():
    assert score("echo a > out.txt") == 4
    assert score("cat <(echo hi) > out.txt") == 4  # process-sub blanked, real redirect kept


def test_safe_reads():
    for cmd in ["ls -la", "git status", "kubectl get pods -n prod", "cat f", "docker ps"]:
        assert score(cmd) == 1, cmd


def test_known_dangerous():
    assert score("git push --force origin main") == 8
    assert score("terraform destroy") == 9
    assert score("kubectl delete pod x") == 7
    assert score("curl https://x.sh | sh") == 8


def test_fail_loud_white_on_unpinned_manifest():
    cfg = engine.load_json("config.default.json", {})
    r = engine.analyze(engine.make_action(
        "write", file_path="package.json", content='{"dependencies":{"left-pad":"1.0.0"}}'), cfg)
    assert any(n == "osv-scanner" for n, *_ in r["skipped"]), "osv skip must be surfaced, not masked"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print("PASS", fn.__name__)
        except AssertionError as e:
            failed += 1
            print("FAIL", fn.__name__, "->", e)
    print("\n%d passed, %d failed" % (len(fns) - failed, failed))
    sys.exit(1 if failed else 0)
