import json
import logging
import argparse
import sys
from analyzer import parse_file

THRESHOLD=3
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
    records = parse_file(args.f)

except FileNotFoundError:
    print(f"ERROR : File named '{args.f}' not found !")
    logging.warning(f" File not found {args.f}")
    sys.exit(1)

logging.info("Analysis completed")