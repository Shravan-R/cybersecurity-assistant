# tests/test_password_checker.py
from ai_agent.password_checker import PasswordChecker

def test_password_strength_and_pwned(monkeypatch):
    pc = PasswordChecker()

    # mock _hibp_k_anonymity to avoid online call
    monkeypatch.setattr(pc, "_hibp_k_anonymity", lambda s: 0)

    res = pc.check_password("Str0ngP@ssw0rd!")
    assert "entropy_bits" in res
    assert res["pwned_count"] == 0
    assert res["compromised"] is False
    assert res["strength"] in ("very_weak", "weak", "reasonable", "strong")
