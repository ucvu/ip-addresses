from webapp.security import SecretBox


def test_secret_box_roundtrip(tmp_path):
    box = SecretBox(tmp_path / "key")
    encrypted = box.encrypt("router-password")
    assert encrypted != "router-password"
    assert box.decrypt(encrypted) == "router-password"
    assert "router-password" not in (tmp_path / "key").read_text()
