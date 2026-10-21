from analyzer import parse_line


def test_parse_line_failed_login_with_ip():
    line = "2026-09-30 10:15:30 ERROR Login failed user=admin ip=192.168.1.50"
    result = parse_line(line)
    assert result["user"] == "admin"
    assert result["ip"] == "192.168.1.50"
    
    
def test_parse_line_failed_login_without_ip():
    line="2026-10-31 22:15:54 ERROR Login failed user=Muhammed"
    result=parse_line(line)
    assert result["user"]=="Muhammed"
    assert result["ip"]==None