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


def report(cmd, cwd=NO_REPO, hooks_installed=False):
    """`hooks_installed` is pinned rather than read from the machine: whether riskscan's git
    hooks happen to be installed on this box must not decide whether a test passes."""
    real = engine.git_hooks_installed
    engine.git_hooks_installed = lambda cwd=None: hooks_installed
    try:
        return engine.analyze(engine.make_action("command", command=cmd, cwd=cwd), BUILTIN_ONLY)
    finally:
        engine.git_hooks_installed = real


def score(cmd):
    return report(cmd)["overall"]


def secret_findings(report):
    """The secrets surface's own verdict. `overall` is useless for a git command now: policy
    pins every version-control write at 10, so a test asserting on it would pass regardless
    of whether the scan found anything."""
    return [(sc, lbl) for n, sc, lbl in report["findings"] if n == "builtin:secrets"]


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


def test_unchecked_version_control_writes_are_top_of_scale():
    """With no authoritative scan downstream, content entering git is top-of-scale: the agent
    layer is the only thing looking."""
    for cmd in ["git add -A", "git commit -m wip", "git push origin main", "git add -p file"]:
        assert score(cmd) == 10, cmd
    for cmd in ["git status", "git log --oneline", "git diff HEAD~1", "git show abc123"]:
        assert score(cmd) == 1, cmd


def test_installed_hooks_retire_the_policy_score():
    """Once the hooks block at commit and push, the synthetic score adds nothing and would fire
    on every routine commit. The same question that silences the ⚪ handoff silences this."""
    for cmd in ["git add -A", "git commit -m wip", "git push origin feature/x"]:
        r = report(cmd, hooks_installed=True)
        # assert the policy contribution is gone, not an exact total: a local custom_rules.json
        # may legitimately score these commands for unrelated reasons.
        assert not any(lbl.startswith("git: writes to version control")
                       for _, _, lbl in r["findings"]), cmd
        assert r["overall"] < 10, (cmd, r["findings"])


def test_a_real_finding_leads_the_banner():
    """The policy line outscores a credential, so ranking by score alone would bury the bullet
    the user most needs to read."""
    r = {"surfaces": ["bash", "secrets"], "skipped": [], "overall": 10,
         "state": engine.state_of(10),
         "findings": [("builtin:bash", 10, engine.POLICY_LABEL),
                      ("builtin:secrets", 9, "GitHub token — .env:1 (staged)")]}
    body = engine.render_banner(r).splitlines()
    assert "GitHub token" in body[1], body
    assert "writes to version control" in body[2], body


def test_known_dangerous():
    assert score("git push --force origin main") == 10  # version-control write dominates
    assert score("terraform destroy") == 9
    assert score("kubectl delete pod x") == 7
    assert score("curl https://x.sh | sh") == 8


def test_fail_loud_white_on_unpinned_manifest():
    cfg = engine.load_json("config.default.json", {})
    r = engine.analyze(engine.make_action(
        "write", file_path="package.json", content='{"dependencies":{"left-pad":"1.0.0"}}'), cfg)
    assert any(n == "osv-scanner" for n, *_ in r["skipped"]), "osv skip must be surfaced, not masked"


# ── secrets surface ───────────────────────────────────────────────────────────
# Credential-shaped fixtures, assembled from fragments at runtime. The pre-commit gate scans
# every staged file including this one, so a literal here would block every commit to this repo
# until a per-finding allowlist exists. Same reasoning as scripts/demo-secrets.py.
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"          # AWS's own documented example key id
FAKE_GH = "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
FAKE_ENTROPY = "aB3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ"
_PK = "PRIVATE " + "KEY"
PEM_BODY = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMw"
PEM = "-----BEGIN OPENSSH %s-----\n%s\n-----END OPENSSH %s-----\n" % (_PK, PEM_BODY, _PK)


def write_report(path, content):
    return engine.analyze(engine.make_action("write", file_path=path, content=content), BUILTIN_ONLY)


def test_secret_in_a_write_is_flagged():
    r = write_report("deploy/.env", "DEBUG=1\nAWS_ACCESS_KEY_ID=%s\n" % FAKE_AWS)
    assert r["overall"] == 9, r["findings"]
    assert any("AWS access key id" in lbl and ".env:2" in lbl for _, _, lbl in r["findings"])


def test_private_key_and_token_shapes():
    assert write_report("id_rsa", PEM)["overall"] == 9
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
        assert any(sc == 9 and "app/config.yaml:1" in lbl and "(staged)" in lbl
                   for sc, lbl in secret_findings(r)), r["findings"]
        assert FAKE_AWS not in engine.render_banner(r)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_git_add_skips_fixture_paths():
    d = _git_repo("token: %s\n" % FAKE_GH, filename="tests/fixtures/sample.yaml")
    try:
        r = report("git add -A", cwd=d)
        assert all(sc == 1 for sc, _ in secret_findings(r)), r["findings"]
        assert any("0 file(s)" in lbl for _, lbl in secret_findings(r))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_git_surface_fails_loud_when_changeset_is_unknowable():
    """An unreadable changeset must read ⚪ NOT ANALYZED, never fold into a green."""
    plain = tempfile.mkdtemp(prefix="riskscan-notrepo-")
    try:
        r = report("git add -A", cwd=plain)
        assert not secret_findings(r), "an unreadable changeset must not produce a verdict"
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
        assert any(sc == 9 for sc, _ in secret_findings(r)), r["findings"]
    finally:
        shutil.rmtree(d, ignore_errors=True)
    r = report("git --work-tree=/elsewhere add -A")
    assert any(s == "secrets" and "not resolved here" in reason
               for _, s, reason, _ in r["skipped"])


def test_base64_hidden_key_material():
    """A k8s Secret carries key material base64-encoded; the plaintext rules are blind to it."""
    import base64
    blob = base64.b64encode(PEM.encode()).decode()
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


def test_cd_hands_off_instead_of_guessing():
    """Predicting a shell's working directory is unbounded, and every gap in the prediction is a
    silent false green. Any directory change now hands off to the git hook rather than guessing,
    and must never produce a verdict about the caller's tree."""
    clean = _git_repo("clean: true\n", filename="ok.yaml")
    try:
        for cmd in ['cd /srv/app && git add -A',
                    'D=/srv/app && cd "$D" && git add -A',
                    'cd $(mktemp -d) && git add -A',
                    '(cd /srv/app; git add -A)',
                    '{ cd /srv/app; git add -A; }',
                    'env -C /srv/app git add -A',
                    'pushd /srv/app && git commit -am wip']:
            r = report(cmd, cwd=clean)
            assert not secret_findings(r), (cmd, r["findings"])
            assert any(s == "secrets" and "not resolved here" in reason
                       for _, s, reason, _ in r["skipped"]), (cmd, r["skipped"])
            assert score(cmd) == 10 if "git add" in cmd or "commit" in cmd else True
    finally:
        shutil.rmtree(clean, ignore_errors=True)


def test_handoff_is_silent_once_the_hooks_are_installed():
    """⚪ names what nothing else covers. With the authoritative scan installed it is a handoff,
    not a gap, so the note goes away instead of repeating every commit."""
    clean = _git_repo("clean: true\n", filename="ok.yaml")
    try:
        r = report("cd /srv/app && git add -A", cwd=clean, hooks_installed=True)
        assert r["skipped"] == [], r["skipped"]
        assert not secret_findings(r)
        assert r["overall"] <= 2, r["findings"]  # the hook is the scan; nothing to shout about
    finally:
        shutil.rmtree(clean, ignore_errors=True)


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
        assert any(sc == 9 for sc, _ in secret_findings(r)), r["findings"]
    finally:
        shutil.rmtree(d, ignore_errors=True)
    r = report("git --work-tree=/elsewhere add -A")
    assert any(s == "secrets" and "not resolved here" in reason
               for _, s, reason, _ in r["skipped"])


def test_base64_hidden_key_material():
    """A k8s Secret carries key material base64-encoded; the plaintext rules are blind to it."""
    import base64
    blob = base64.b64encode(PEM.encode()).decode()
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


def test_gitleaks_findings_are_redacted_and_relative():
    """gitleaks' JSON carries the credential in `Secret`/`Match`, and its `File` is the tempdir
    path we materialized. Neither may reach a finding: one leaks the secret, the other leaks a
    path the user cannot act on."""
    if not shutil.which("gitleaks"):
        return  # analyzer absent — the ⚪ path is what runs, covered by the fail-loud tests
    cfg = {"analyzers": {"gitleaks": {"enabled": True}}, "on_missing": "suggest"}
    r = engine.analyze(engine.make_action("write", file_path="deploy/id_ed25519", content=PEM), cfg)
    assert r["overall"] == 9, r["findings"]
    blob = engine.render_banner(r) + engine.render_agent_context(r)
    assert PEM_BODY[:20] not in blob, "gitleaks secret leaked into the banner"
    assert "REDACTED" not in blob, "the redaction placeholder should not be rendered either"
    assert "/var/folders" not in blob and "tmp" not in blob.split("id_ed25519")[0][-40:], \
        "the tempdir path must be stripped from reported locations"


def test_gitleaks_scores_generic_rules_lower():
    assert engine._gl_score("private-key") == 9
    assert engine._gl_score("github-pat") == 9
    assert engine._gl_score("generic-api-key") == engine.GL_GENERIC == 6


def test_gitleaks_parser_rejects_secret_bearing_fields():
    live = "AKIA" + "REALLIVEKEY00000"
    out = engine.parse_gitleaks('[{"RuleID":"aws-access-token","File":"a.env","StartLine":3,'
                                '"Secret":"%s","Match":"key=%s"}]' % (live, live))
    assert out[0] == 9
    assert all(live not in lbl for _, lbl in out[1])
    assert engine.parse_gitleaks("[]") == (1, [(1, "no findings")])
    assert engine.parse_gitleaks("not json") is None


def test_gitleaks_parser_honours_a_path_filter():
    """gitleaks reads the index itself in `git --staged` mode, so it cannot be handed a file
    list. Without filtering its findings, a path policy would govern the builtin and nothing
    would govern gitleaks — which made a fixture credential block or not depending on whether
    an unrelated file happened to be staged alongside it."""
    j = ('[{"RuleID":"github-pat","File":"tests/fixtures/a.env","StartLine":1},'
         ' {"RuleID":"private-key","File":"deploy/key","StartLine":1}]')
    assert len(engine.parse_gitleaks(j)[1]) == 2
    kept = engine.parse_gitleaks(j, skip=lambda p: p.startswith("tests/"))[1]
    assert len(kept) == 1 and "deploy/key" in kept[0][1]


# ── allowlist ─────────────────────────────────────────────────────────────────
def test_allowlist_three_granularities():
    """A line-pinned entry rots when the file shifts, so file-wide and rule-wide forms exist."""
    text = "k=%s\n" % FAKE_AWS
    for entry in ("deploy/.env:aws-access-key-id:1",   # this finding
                  "deploy/.env:aws-access-key-id",     # that rule in that file
                  "aws-access-key-id"):                # that rule everywhere
        sc, fs = engine._secret_scan(text, "deploy/.env", {entry: "known example"})
        assert fs == [], (entry, fs)
    # a near-miss must NOT suppress
    for entry in ("other/.env:aws-access-key-id:1", "deploy/.env:aws-access-key-id:9",
                  "deploy/.env:github-token"):
        sc, fs = engine._secret_scan(text, "deploy/.env", {entry: ""})
        assert sc == 9, (entry, fs)


def test_suppressed_findings_stay_visible():
    """An allowlist that silently drops findings IS the false green this surface exists to
    prevent. You may ignore a finding; you may not make riskscan pretend it never saw one."""
    supp = []
    engine._secret_scan("k=%s\n" % FAKE_AWS, "deploy/.env",
                        {"aws-access-key-id": "documented example"}, supp)
    assert supp == [("deploy/.env:aws-access-key-id:1", "documented example")]
    notes = engine._suppression_notes(supp)
    assert len(notes) == 1
    assert "1 finding(s) suppressed" in notes[0] and "documented example" in notes[0]
    assert engine._suppression_notes([]) == []


def test_allowlist_keeps_the_other_findings():
    text = "k=%s\ntok=%s\n" % (FAKE_AWS, FAKE_GH)
    sc, fs = engine._secret_scan(text, "x.env", {"aws-access-key-id": "ok"})
    assert sc == 9 and len(fs) == 1 and "GitHub token" in fs[0][1]


def test_allowlist_file_is_read_from_an_ancestor_with_its_reason():
    d = tempfile.mkdtemp(prefix="riskscan-ign-")
    try:
        os.makedirs(os.path.join(d, "a", "b"))
        with open(os.path.join(d, ".riskscanignore"), "w") as f:
            f.write("# a comment line\n\nx.env:aws-access-key-id  # vendor sample\n")
        engine._IGNORES_CACHE.clear()
        ig = engine.load_ignores(os.path.join(d, "a", "b"))
        assert ig == {"x.env:aws-access-key-id": "vendor sample"}, ig
    finally:
        engine._IGNORES_CACHE.clear()
        shutil.rmtree(d, ignore_errors=True)


def test_gitleaks_findings_are_allowlisted_too():
    j = '[{"RuleID":"generic-api-key","File":"docs/x.md","StartLine":7}]'
    supp = []
    out = engine.parse_gitleaks(j, ignores={"docs/x.md:generic-api-key:7": "doc sample"},
                                suppressed=supp)
    assert out == (1, [(1, "no findings")]), out
    assert supp == [("docs/x.md:generic-api-key:7", "doc sample")]


def test_skip_paths_are_no_longer_silent():
    """Same defect as a silent allowlist: a skipped path produced no output at all, so a real
    credential in a fixture tree was invisible rather than excused."""
    d = _git_repo("token: %s\n" % FAKE_GH, filename="tests/fixtures/s.yaml")
    try:
        r = report("git add -A", cwd=d)
        assert any("skip_paths" in reason for _, _, reason, _ in r["skipped"]), r["skipped"]
    finally:
        shutil.rmtree(d, ignore_errors=True)


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
