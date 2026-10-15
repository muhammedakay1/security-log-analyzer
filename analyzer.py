import re
from datetime import datetime


def parse_line(line):

    pattern = r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<level>[A-Z]+) Login +(?P<event>failed|successful) user=(?P<user>\S+)(?: ip=(?P<ip>\S+))?"
    match = re.match(pattern, line)
    if match is None:
       return None
    
    return {"timestamp":datetime.strptime(match.group("timestamp"),"%Y-%m-%d %H:%M:%S"),
            "level":match.group("level"),
            "event":match.group("event"),
            "user":match.group("user"),
            "ip":match.group("ip")
            }

def parse_file(path):
        records=[]
        with open (path) as f:
            for line in f:
                a=parse_line(line)
                if a is not None:
                    records.append(a)
            return records
        
print(parse_file("logs/sample.log"))