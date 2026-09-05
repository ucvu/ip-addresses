from core.executor import IsolatedCliExecutor
from core.models import OperationOptions, RouterCredentials, RouterTarget


def test_executor_forces_utf8_for_child_process(tmp_path, monkeypatch):
    captured = {}

    class Process:
        stdout = []

        def wait(self):
            return 0

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return Process()

    monkeypatch.setattr("core.executor.subprocess.Popen", fake_popen)
    executor = IsolatedCliExecutor(tmp_path, tmp_path, lambda event: None)
    result = executor.run(
        RouterTarget(1, "Home", "192.168.1.1"),
        RouterCredentials("admin", "password"),
        OperationOptions(action="update", preset_id=1),
        tmp_path / "preset.txt",
    )
    assert result == 0
    assert captured["encoding"] == "utf-8"
    assert captured["env"]["PYTHONIOENCODING"] == "utf-8"
    assert captured["env"]["PYTHONUTF8"] == "1"
    assert captured["env"]["PYTHONUNBUFFERED"] == "1"
    assert captured["command"][1] == "-u"
