"""Engine regression tests. Zero-dependency: run with `python3 tests/test_engine.py`
(or `pytest`). Guards the scoring bands and the false-positive fixes."""
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from riskscan import engine  # noqa: E402

BUILTIN_ONLY = {"analyzers": {"builtin": {"enabled": True}}, "on_missing": "suggest"}
# Command tests pin a non-repo cwd so the git/secrets surface cannot make a bash
# assertion depend on whatever is uncommitted in the checkout the tests run from.
NO_REPO = os.path.join(tempfile.gettempdir(), "riskscan-tests-no-such-dir")


def report(cmd, cwd=NO_REPO):
    return engine.analyze(engine.make_action("command", command=cmd, cwd=cwd), BUILTIN_ONLY)


def score(cmd):
    return report(cmd)["overall"]


def top_label(cmd):
    r = report(cmd)
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


# ── secrets surface ───────────────────────────────────────────────────────────
# Fake credentials that match the rules' *shape* only. AKIAIOSFODNN7EXAMPLE is AWS's
# own documented example key.
FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"
FAKE_GH = "ghp_0123456789abcdefghijABCDEFGHIJ012345"
FAKE_ENTROPY = "aB3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ"


def write_report(path, content):
    return engine.analyze(engine.make_action("write", file_path=path, content=content), BUILTIN_ONLY)


def test_secret_in_a_write_is_flagged():
    r = write_report("deploy/.env", "DEBUG=1\nAWS_ACCESS_KEY_ID=%s\n" % FAKE_AWS)
    assert r["overall"] == 9, r["findings"]
    assert any("AWS access key id" in lbl and ".env:2" in lbl for _, _, lbl in r["findings"])


def test_private_key_and_token_shapes():
    assert write_report("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n")["overall"] == 9
    assert write_report("ci.yml", "token: %s" % FAKE_GH)["overall"] == 9


def test_findings_never_contain_the_secret():
    """The banner reaches the transcript, the log and the model's context — a finding that
    quoted the match would create the exposure this surface exists to prevent."""
    content = "key=%s\ntok=%s\napi_key = \"%s\"\n" % (FAKE_AWS, FAKE_GH, FAKE_ENTROPY)
    r = write_report("conf.yaml", content)
    blob = engine.render_banner(r) + engine.render_agent_context(r)
    for secret in (FAKE_AWS, FAKE_GH, FAKE_ENTROPY):
        assert secret not in blob, "secret value leaked into riskscan output"
    assert "AKIA" not in blob and "ghp_" not in blob


def test_entropy_gate_on_generic_assignments():
    assert write_report("a.py", 'api_key = "%s"' % FAKE_ENTROPY)["overall"] == 6
    # placeholders, templated references, low entropy and digests must stay green
    for content in ['password = "changeme-please-now"',
                    'token = "${VAULT_TOKEN_VALUE}"',
                    'api_key = "aaaaaaaaaaaaaaaaaaaa"',
                    'secret = "{{ .Values.someSecret }}"',
                    'integrity_token = "a3f5b9c1d7e2a3f5b9c1d7e2a3f5b9c1"']:
        assert write_report("a.yaml", content)["overall"] == 1, content


def _git_repo(content, filename="app/config.yaml"):
    d = tempfile.mkdtemp(prefix="riskscan-git-")
    subprocess.run(["git", "init", "-q", d], check=True)
    path = os.path.join(d, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    return d


def test_git_add_scans_what_would_be_staged():
    d = _git_repo("aws_access_key_id: %s\n" % FAKE_AWS)
    try:
        r = report("git add -A && git commit -m wip", cwd=d)
        assert r["overall"] == 9, r["findings"]
        assert any("app/config.yaml:1" in lbl and "(staged)" in lbl for _, _, lbl in r["findings"])
        assert FAKE_AWS not in engine.render_banner(r)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_git_add_skips_fixture_paths():
    d = _git_repo("token: %s\n" % FAKE_GH, filename="tests/fixtures/sample.yaml")
    try:
        r = report("git add -A", cwd=d)
        assert r["overall"] == 2, r["findings"]  # the bash pack's baseline, no secret finding
        assert any("0 file(s)" in lbl for n, _, lbl in r["findings"] if n == "builtin:secrets")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_git_surface_fails_loud_when_changeset_is_unknowable():
    """An unreadable changeset must read ⚪ NOT ANALYZED, never fold into a green."""
    plain = tempfile.mkdtemp(prefix="riskscan-notrepo-")
    try:
        r = report("git add -A", cwd=plain)
        assert r["overall"] == 2  # the bash pack's verdict only — no green secrets finding
        assert any(s == "secrets" and "not a git repository" in reason
                   for _, s, reason, _ in r["skipped"])
    finally:
        shutil.rmtree(plain, ignore_errors=True)
    # and when the runtime gave us no directory at all
    assert any(s == "secrets" and "no working directory" in reason
               for _, s, reason, _ in report("git add -A")["skipped"])


def test_push_without_upstream_is_not_analyzed():
    d = _git_repo("ok: 1\n")
    try:
        r = report("git push origin HEAD", cwd=d)
        assert any(s == "secrets" and "upstream" in reason for _, s, reason, _ in r["skipped"])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_git_dash_c_resolves_the_named_repo():
    """`git -C <dir> add` must be scanned in <dir>, not in the caller's cwd — resolving the
    wrong tree would report a green for a changeset nobody looked at."""
    d = _git_repo("aws_access_key_id: %s\n" % FAKE_AWS)
    try:
        r = report("git -C %s add -A" % d, cwd=NO_REPO)
        assert r["overall"] == 9, r["findings"]
    finally:
        shutil.rmtree(d, ignore_errors=True)
    r = report("git --work-tree=/elsewhere add -A")
    assert any(s == "secrets" and "cannot tell which tree" in reason
               for _, s, reason, _ in r["skipped"])


def test_base64_hidden_key_material():
    """A k8s Secret carries key material base64-encoded; the plaintext rules are blind to it."""
    import base64
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
    blob = base64.b64encode(pem.encode()).decode()
    r = write_report("sealed-secret.yaml", "data:\n  id_rsa: %s\n" % blob)
    assert r["overall"] == 9, r["findings"]
    assert any("base64-encoded" in lbl for _, _, lbl in r["findings"])


def test_unquoted_values_score_the_same_as_quoted():
    for content in ['db:\n  password: %s\n' % FAKE_ENTROPY, 'db:\n  password: "%s"\n' % FAKE_ENTROPY]:
        assert write_report("values.yaml", content)["overall"] == 6, content


def test_identifiers_and_urls_are_not_credentials():
    for content in ["secretName: my-app-tls-certificate-secret",
                    "token_url: https://login.example.com/oauth2/v2.0/token",
                    "private_key_path: /etc/ssl/private/tls.key",
                    "image_pull_secret: regcred-internal-registry"]:
        assert write_report("values.yaml", content)["overall"] == 1, content


def test_public_key_material_is_not_flagged():
    pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKx3Qk1vZXhhbXBsZXB1YmxpY2tleWRhdGE demo\n"
    assert write_report("id_ed25519.pub", pub)["overall"] == 1


def test_cd_before_git_is_followed():
    """`cd <repo> && git add -A` must be scanned in <repo>. Resolving the caller's cwd instead
    reported a confident "no credential pattern in 1 file(s)" for a tree holding an AWS key."""
    secret = _git_repo("aws_access_key_id: %s\n" % FAKE_AWS)
    clean = _git_repo("clean: true\n", filename="ok.yaml")
    try:
        r = report("cd %s && git add -A" % secret, cwd=clean)
        assert r["overall"] == 9, r["findings"]
        assert any("app/config.yaml" in lbl for _, _, lbl in r["findings"])
        # a relative hop must work too
        r = report("cd app && git add -A", cwd=secret)
        assert r["overall"] == 9, r["findings"]
    finally:
        shutil.rmtree(secret, ignore_errors=True)
        shutil.rmtree(clean, ignore_errors=True)


def test_shell_variables_are_resolved_where_possible():
    """A literal assignment earlier in the same command, or a variable in the environment, is
    resolvable without executing anything — so `D=<repo> && cd "$D" && git add` must be scanned."""
    secret = _git_repo("aws_access_key_id: %s\n" % FAKE_AWS)
    clean = _git_repo("clean: true\n", filename="ok.yaml")
    try:
        for cmd in ['D=%s && cd "$D" && git add -A' % secret,
                    'REPO=%s; cd ${REPO} && git add -A' % secret]:
            r = report(cmd, cwd=clean)
            assert r["overall"] == 9, (cmd, r["findings"])
        os.environ["RISKSCAN_TEST_REPO"] = secret
        try:
            r = report('cd "$RISKSCAN_TEST_REPO" && git add -A', cwd=clean)
            assert r["overall"] == 9, r["findings"]
        finally:
            del os.environ["RISKSCAN_TEST_REPO"]
    finally:
        shutil.rmtree(secret, ignore_errors=True)
        shutil.rmtree(clean, ignore_errors=True)


def test_cd_that_needs_execution_is_not_analyzed():
    """What is left after static resolution: command substitution, shell history, globs.
    Evaluating those would mean running an unapproved command to vet it — so they read ⚪,
    never the caller's tree."""
    clean = _git_repo("clean: true\n", filename="ok.yaml")
    try:
        cases = [("cd $(mktemp -d) && git add -A", "without running the command"),
                 ('cd "$RISKSCAN_DEFINITELY_UNSET" && git add -A', "without running the command"),
                 ("cd - && git add -A", "shell history"),
                 ("cd /tmp/build-* && git add -A", "is a glob")]
        for cmd, expect in cases:
            r = report(cmd, cwd=clean)
            assert any(s == "secrets" and expect in reason
                       for _, s, reason, _ in r["skipped"]), (cmd, r["skipped"])
            assert not any(n == "builtin:secrets" and "no credential pattern" in lbl
                           for n, _, lbl in r["findings"]), cmd
    finally:
        shutil.rmtree(clean, ignore_errors=True)


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
