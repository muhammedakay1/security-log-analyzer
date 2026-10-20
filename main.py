import json
import logging
import argparse
import sys
from analyzer import parse_file,count_failed_by_ip, count_failed_by_user, get_failed_times_by_ip, get_failed_hack_ip, find_suspicious, find_success_after_failures


parser=argparse.ArgumentParser(description="Analyze login logs for suspicious activity")

parser.add_argument("-f", help="Path to the log file",required=True)
parser.add_argument("--output", default="report.json", help="Path of the JSON report")
parser.add_argument("--threshold",type=int,default=3)
args=parser.parse_args()


logging.basicConfig(
    filename="analysis.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s -%(message)s"
)

logging.info("Analysis started")

try:
    records = parse_file(args.f)

except FileNotFoundError:
    print(f"ERROR : File named '{args.f}' not found !")
    logging.warning(f" File not found {args.f}")
    sys.exit(1)

if not records:
    print("No valid log lines found")
    logging.warning("No valid log lines found")
    sys.exit(1)


failed_by_ip = count_failed_by_ip(records)
failed_by_user = count_failed_by_user(records)

failed_times = get_failed_times_by_ip(records)

attacker_ips = get_failed_hack_ip(failed_times, 5, 3)

suspicious_ips = find_suspicious(failed_by_ip, args.threshold)
suspicious_users = find_suspicious(failed_by_user, args.threshold)

successful_after_failures = find_success_after_failures(records, 60, 3)

print("Brute-force IPs:", attacker_ips)
print("Suspicious IPs:", suspicious_ips)
print("Suspicious users:", suspicious_users)
print("Successful logins after failures:")

for record in successful_after_failures:
    print("User:", record["user"], "| IP:", record["ip"])

success_list = []
for record in successful_after_failures:
    item = {
        "user": record["user"],
        "ip": record["ip"],
        "timestamp": str(record["timestamp"])
    }
    success_list.append(item)

report = {
    "attacker_ips": attacker_ips,
    "suspicious_ips": suspicious_ips,
    "suspicious_users": suspicious_users,
    "failed_by_ip": failed_by_ip,
    "failed_by_user": failed_by_user,
    "successful_after_failures": success_list
}

with open(args.output, "w") as f:
    json.dump(report, f, indent=4)


logging.info("Analysis completed")

if attacker_ips or successful_after_failures:
    sys.exit(2)