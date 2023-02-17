#!/usr/bin/env python3

from eventlog import eventlog
import argparse
import json
import yaml

def main():
    parser = argparse.ArgumentParser(
        description ="Dump an eventlog to JSON"
    )

    parser.add_argument(
        "-f",
        "--file",
        help="binary event log file"
    )

    parser.add_argument(
        "-y",
        "--yaml",
        help="yaml reference file"
    )

    
    args = parser.parse_args()
    assert args.file, "file argument is required"

    with open (args.file, 'rb') as fp:
        buffer = fp.read()
        testlogbin = eventlog.EventLog(buffer, len(buffer))
        testlog = json.dumps(testlogbin, default=lambda o: o.toJson(), sort_keys=True)

    with open (args.yaml, 'r') as fp:
        reflogdict = yaml.load (fp, Loader = yaml.Loader)
        reflog = json.dumps(reflogdict, sort_keys=True)
        

    testlog1 = json.loads(testlog)
    reflog1 = json.loads(reflog)['events']

    for idx in range(0, len(testlog1)):
        testevent = testlog1[idx]
        refevent = reflog1[idx]
        if testevent != refevent:
            print('---------------')
            print(json.dumps(refevent, indent=4))
            print(json.dumps(testevent, indent=4))
        
        
main()
