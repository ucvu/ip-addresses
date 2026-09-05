from pathlib import Path


def test_live_log_has_pause_copy_and_no_automatic_reload():
    template = (Path(__file__).parents[1] / "webapp" / "templates" / "job_detail.html").read_text(encoding="utf-8")
    assert 'id="toggle-live"' in template
    assert 'id="copy-log"' in template
    assert 'id="auto-scroll"' in template
    assert "location.reload" not in template
    assert "buffer.push" in template
    assert "/actions" in template
    assert "updateCsrf" in template
    assert "addEventListener('submit'" in template
