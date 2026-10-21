from datetime import datetime

from analyzer import find_suspicious, has_burst, parse_line


def test_parse_line_failed_login_with_ip():
    line = "2026-09-30 10:15:30 ERROR Login failed user=admin ip=192.168.1.50"
    result = parse_line(line)
    assert result["user"] == "admin"
    assert result["ip"] == "192.168.1.50"


def test_parse_line_failed_login_without_ip():
    line = "2026-10-31 22:15:54 ERROR Login failed user=Muhammed"
    result = parse_line(line)
    assert result["user"] == "Muhammed"
    assert result["ip"] is None


def test_parse_line_empty_line():
    result = parse_line("")
    assert result is None


def test_parse_line_dotted_user_and_ipv6():
    line = "2026-09-30 10:15:30 ERROR Login failed user=john.doe ip=2001:db8::1"
    result = parse_line(line)
    assert result["user"] == "john.doe"
    assert result["ip"] == "2001:db8::1"


def test_has_burst_detects_fast_attempts():
    times = [
        datetime(2026, 9, 30, 10, 15, 30),
        datetime(2026, 9, 30, 10, 15, 31),
        datetime(2026, 9, 30, 10, 15, 32),
    ]
    result = has_burst(times, 5, 3)
    assert result is True


def test_has_burst_ignores_slow_attempts():
    times = [
        datetime(2026, 9, 30, 10, 0, 0),
        datetime(2026, 9, 30, 10, 10, 0),
        datetime(2026, 9, 30, 10, 20, 0),
    ]
    result = has_burst(times, 5, 3)
    assert result is False


def test_find_suspicious_returns_names_above_threshold():
    counts = {"a": 4, "b": 1}
    result = find_suspicious(counts, 3)
    assert result == ["a"]
