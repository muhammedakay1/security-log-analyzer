# Security Log Analyzer

A small Python command-line tool that analyzes login logs and flags suspicious activity such as brute-force attempts and successful logins that follow repeated failures.

## Features

- Parses login log lines into structured records
- Counts failed logins per IP address and per user
- Detects brute-force attempts (several failed logins from one IP within a short time window)
- Flags suspicious IPs and users above a configurable failure threshold
- Detects successful logins that follow repeated failed logins from the same IP (possible account takeover)
- Writes a JSON report and an analysis log

## Requirements

- Python 3
- No external libraries

## Usage

```bash
python3 main.py -f logs/sample.log
```

Options:

| Option | Description | Default |
|---|---|---|
| `-f` | Path to the log file (required) | - |
| `--output` | Path of the JSON report | `report.json` |
| `--threshold` | Failed logins needed to flag an IP or user as suspicious | `3` |

Exit codes:

- `0`: analysis finished, nothing suspicious found
- `1`: error (file not found or no valid log lines)
- `2`: suspicious activity found

## Log format

One event per line:

```
2026-09-30 10:15:30 ERROR Login failed user=admin ip=192.168.1.50
2026-09-30 10:15:21 INFO Login successful user=muhammed ip=192.168.1.20
```

The `ip=` field is optional. Lines that do not match this format are ignored.

## Example output

```
Brute-force IPs: ['192.168.1.50']
Suspicious IPs: ['192.168.1.50']
Suspicious users: ['admin']
Successful logins after failures:
User: admin | IP: 192.168.1.50
```

## How detection works

- **Brute-force:** 3 or more failed logins from the same IP within 5 seconds.
- **Suspicious IP / user:** the number of failed logins is greater than or equal to the threshold. The right threshold depends on the system: a busy public website can use a higher value, while a sensitive system (for example an admin panel) should use a lower one.
- **Success after failures:** a successful login from an IP that had at least 3 failed logins in the 60 seconds before it.

## Interpreting results

The results are warning signs, not proof of an attack. A user may simply have forgotten a password or mistyped it. An analyst should check the flagged IP and, if needed, contact the account owner to confirm the activity (for example: "We detected a suspicious login on your account. Was this you?"). If the owner does not recognize it, the password should be reset and active sessions closed.

## Project structure

- `main.py`: command-line entry point, prints results and writes the report
- `analyzer.py`: parsing and detection functions
- `logs/sample.log`: sample log file

## Limitations

- Supports only the log format shown above
- The brute-force window (5 seconds, 3 attempts) and the success-after-failures window (60 seconds, 3 attempts) are fixed in the code; `--threshold` only affects suspicious IPs and users
- Failed logins without an IP are counted per user but not per IP
- No automated tests yet

## Disclaimer

Use this tool only on logs from systems you own or are authorized to analyze.