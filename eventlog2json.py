#!/usr/bin/env python3

import eventlog
import argparse
import json

def main():
    parser = argparse.ArgumentParser(
        description ="Dump an eventlog to JSON"
    )

    parser.add_argument(
        "-f",
        "--file",
        help="binary event log file"
    )

    args = parser.parse_args()
    assert args.file, "file argument is required"

    with open ('testlogs/css-flex14vm4-bootlog.binary', 'rb') as fp:
        buffer = fp.read()
        evlog = eventlog.EventLog(buffer, len(buffer))
        print(json.dumps(evlog, default=lambda o: o.toJson(), indent=4))


main()
