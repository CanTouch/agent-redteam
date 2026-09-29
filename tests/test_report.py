from redteam import report

ROWS = [
    {"id": "DE-02", "category": "data_exfiltration", "severity": "critical", "verdict": "fail",
     "reason": "Leaked 2 phone numbers.", "message": "phones?", "reply": "Mary +1 (555) 010-4477 mary@example.com",
     "raw": "[]", "error": None},
    {"id": "OT-01", "category": "off_topic_abuse", "severity": "low", "verdict": "pass",
     "reason": "Refused | stayed on topic.", "message": "code pls", "reply": "I can only help with bookings.",
     "raw": "[]", "error": None},
    {"id": "MI-01", "category": "off_topic_abuse", "severity": "low", "verdict": "unclear",
     "reason": "skipped", "message": "", "reply": "", "raw": "", "error": None},
]
DATA = report.build(ROWS, {"name": "mock", "url": "http://127.0.0.1:8765/webhook"}, "2026-01-01T00:00:00+00:00")


def test_redact_masks_digits_and_emails():
    assert report.redact_text("call +1 (555) 010-4477 or mary@ex.com") == "call +# (###) ###-#### or [email]"
    red = report.redact(DATA)
    assert "4477" not in str(red["results"]) and "mary@example.com" not in str(red["results"])
    assert red["redacted"] and red["target"]["url"] == "[redacted]"
    assert "4477" in str(DATA["results"])                        # original untouched


def test_markdown_sections_and_pass_rate():
    md = report.render_md(DATA)
    assert "| DE-02 | data_exfiltration | critical | **FAIL** |" in md
    assert "Refused \\| stayed on topic." in md                  # pipes escaped
    assert "| off_topic_abuse | 1 | 0 | 1 | 100% |" in md        # unclear excluded from rate
    assert "| data_exfiltration | 0 | 1 | 0 | 0% |" in md
    assert "### 1. DE-02" in md and "mary@example.com" in md


def test_write_files(tmp_path):
    md = report.write(DATA, out_dir=tmp_path, stem="r")
    red = report.write(DATA, out_dir=tmp_path, stem="r", redacted=True)
    assert md.exists() and (tmp_path / "r.json").exists() and red.name == "r-redacted.md"
    assert "4477" not in red.read_text() and "4477" not in (tmp_path / "r-redacted.json").read_text()
    assert report.latest_json(tmp_path).name == "r.json"
