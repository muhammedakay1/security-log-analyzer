import re
import json
from collections import Counter
import logging
import argparse
import sys
from datetime import datetime

THRESHOLD=3
brute_force_ips = {}
suspicious_users = 0
suspicious_ips = 0
parser=argparse.ArgumentParser(description="logs/sample.log")

parser.add_argument("-f", required=True)

args=parser.parse_args()


logging.basicConfig(
    filename="analysis.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s -%(message)s"
)

logging.info("Analysis started")

try:
    with open(args.f,"r") as f:
        log=f.read()

except FileNotFoundError:
    print(f"ERROR : File named '{args.f}' not found !")
    logging.warning(f" File not found {args.f}")
    sys.exit(1)



failed_user=re.findall(r".*Login failed.* user=([\w]+)",log)
failed=re.findall(r".*Login failed.* ip=([\d.]+)",log)
successful=re.findall(r".*Login successful.* ip=([\d.]+)",log)
times=re.findall(r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}) .*Login failed.* ",log)
all_times = re.findall(r"\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}", log)
levels=re.findall(r"INFO|ERROR|WARNING",log)
level_counter=counter=Counter(levels)
failed_times = [datetime.strptime(time, "%Y-%m-%d %H:%M:%S") for time in times]
ip_times={}

for i in range(len(failed)):
    ip= failed[i]
    if ip in ip_times:
        ip_times[ip].append(failed_times[i])
    else:
        ip_times[ip] = [failed_times[i]]
for ip, times in ip_times.items():
    if len(times) >= 3:
        for i in range(len(times) - 2):
            difference = times[i + 2] - times[i]

            if difference.total_seconds() <= 5:
                attempts = 3
                for j in range(i + 3, len(times)):
                    if (times[j] - times[i]).total_seconds() <= 5:
                        attempts += 1
                    else:
                        break
                brute_force_ips[ip] = {
                    "attempts": attempts,
                    "window_seconds": 5
                    }
                break


if brute_force_ips:
    print("WARNING: Possible brute-force attack detected")
    logging.warning(f"Possible brute-force attack detected: {brute_force_ips}")
counter=Counter(failed)
user_counter=Counter(failed_user)

report={
    "total_successful_logins":len(successful),
    "total_failed_logins":sum(counter.values()),
    "brute_force_detected": bool(brute_force_ips),
    "brute_force_ips": brute_force_ips,
    "users": {},
    "ips": {},
}

for user,count in user_counter.items():
    if count>=THRESHOLD:
        print(f"{user} {count} ")
        print("WARNING: Suspicious user detected")
        logging.warning(f"Suspicious user detected {user} {count}")
        suspicious_users += 1
        report["users"][user]={
             "failed_attempts":count,
            "suspicious":True,
            
        }
    else:
        print(f"{user} {count} ")
        report["users"][user]={
               "failed_attempts":count,
            "suspicious":False,
           
        }

for ip, count in counter.items():
    if count>=THRESHOLD:
        print(f"{ip} {count} failed attempts ")
        print("WARNING: Suspicious IP detected")
        logging.warning(f"Suspicious IP detected {ip} {count}")
        suspicious_ips += 1
        report["ips"][ip]={
            "failed_attempts":count,
            "suspicious":True,
            
        }
    else:
        report["ips"][ip]={
             "failed_attempts":count,
            "suspicious":False,
           
        }
        print(f"{ip} {count}")

report["summary"]={
        "total_users":len(user_counter),
        "total_ips":len(counter),
        "suspicious_users":suspicious_users,
        "suspicious_ips":suspicious_ips,
        "first_log": all_times[0],
        "last_log": all_times[-1],
        "log_levels": dict(level_counter),
        
}
with open("report.json","w") as f:
    json.dump(report,f,indent=4)

logging.info("Analysis completed")

