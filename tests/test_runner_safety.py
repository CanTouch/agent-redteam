import pytest

from redteam import runner

T = {"name": "t", "url": "http://127.0.0.1:1/webhook", "method": "POST", "headers": {},
     "body_template": {"message": "{{message}}"}, "response_path": "0.output", "canaries": []}


def test_url_not_in_allowlist_is_refused():
    with pytest.raises(runner.SafetyError):
        runner.Runner(T, allowlist={"http://127.0.0.1:2/other"})


def test_allowlist_rechecked_on_every_send():
    rn = runner.Runner(T, allowlist={T["url"]}, interval=0)
    rn.target = {**T, "url": "https://evil.example.com/hook"}
    with pytest.raises(runner.SafetyError):
        rn.send("hi")


def test_fast_rate_only_allowed_for_loopback():
    remote = {**T, "url": "https://n8n.example.com/webhook/x"}
    with pytest.raises(runner.SafetyError):
        runner.Runner(remote, allowlist={remote["url"]}, interval=0)
    runner.Runner(remote, allowlist={remote["url"]})  # default 2 s is fine


def test_cli_refuses_unknown_target(capsys):
    import cli
    with pytest.raises(SystemExit) as e:
        cli.main(["run", "--target", "https://evil.example.com", "--yes", "--no-llm"])
    assert "Unknown target" in str(e.value)


def test_cli_requires_typing_yes(monkeypatch):
    import cli
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    monkeypatch.setattr(runner.Runner, "send", lambda *a: pytest.fail("nothing may be sent"))
    with pytest.raises(SystemExit) as e:
        cli.main(["run", "--target", "mock", "--no-llm"])
    assert "Aborted" in str(e.value)


def test_rate_limiter_spaces_requests():
    now, sleeps = [0.0], []
    rl = runner.RateLimiter(2.0, clock=lambda: now[0], sleep=lambda s: (sleeps.append(s), now.__setitem__(0, now[0] + s)))
    rl.wait(); now[0] += 0.5; rl.wait(); rl.wait()
    assert sleeps == [pytest.approx(1.5), pytest.approx(2.0)]


def test_extract_dotted_paths():
    assert runner.extract([{"output": "hi"}], "0.output") == "hi"
    assert runner.extract({"data": {"reply": "x"}}, "data.reply") == "x"
    assert runner.extract({"data": {}}, "data.reply") is None
    assert runner.extract("raw", "") == "raw"


def test_env_expansion(monkeypatch):
    monkeypatch.setenv("TOKEN_X", "s3cret")
    assert runner.expand_env("Bearer ${TOKEN_X}") == "Bearer s3cret"
    with pytest.raises(runner.SafetyError):
        runner.expand_env("${DEFINITELY_NOT_SET_123}")


def test_attack_library_shape():
    attacks = runner.load_attacks()
    assert len(attacks) == 24 and len({a["id"] for a in attacks}) == 24
    cats = {}
    for a in attacks:
        cats[a["category"]] = cats.get(a["category"], 0) + 1
        assert a["severity"] in ("critical", "high", "medium", "low") and a["success_if"]
    assert cats == {c: 3 for c in ("prompt_injection", "data_exfiltration", "authority_spoof", "jailbreak_roleplay",
                                   "malformed_input", "opt_out_compliance", "off_topic_abuse", "multilingual")}
    assert max(len(a["message"]) for a in attacks) == 5000 and min(len(a["message"]) for a in attacks) == 0


def test_targets_yaml_only_has_loopback_mock_by_default():
    targets = runner.load_targets()
    assert "mock" in targets and runner.is_loopback(targets["mock"]["url"])


def test_redirects_are_never_followed():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from redteam import judge

    hits = []

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append(self.path)
            self.send_response(200); self.end_headers(); self.wfile.write(b'[{"output":"leak"}]')
        def log_message(self, *a): pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    sink_url = f"http://127.0.0.1:{sink.server_address[1]}/elsewhere"

    class Redirect(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(307); self.send_header("Location", sink_url); self.end_headers()
        def log_message(self, *a): pass

    redir = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    for s in (sink, redir):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{redir.server_address[1]}/webhook"
        sent = runner.Runner({**T, "url": url}, allowlist={url}, interval=0).send("hi")
        assert hits == [] and sent["status"] == 307 and "not followed" in sent["error"]
        assert judge.judge({"message": "hi"}, sent, [])["verdict"] == "unclear"
    finally:
        sink.shutdown(); redir.shutdown()
