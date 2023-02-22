#!/usr/bin/env python3

from eventlog import eventlog
import argparse
import json
import yaml
import time
import glob
import os

def main():
    parser = argparse.ArgumentParser(
        description ="Dump an eventlog to JSON"
    )
    parser.add_argument(
        '-d',
        '--dir',
        help='directory where raw and yaml logs are kept')

    args = parser.parse_args()
    compare_dir(args.dir)

def binary2json(binarylogfile: str):
    with open (binarylogfile, 'rb') as fp:
        buffer = fp.read()
        testlogbin = eventlog.EventLog(buffer, len(buffer))
        testlog = json.dumps(testlogbin, default=lambda o: o.toJson(), sort_keys=True)
        return testlog

def yaml2json(yamlfile: str):
    with open (yamlfile, 'r') as fp:
        reflogdict = yaml.load (fp, Loader = yaml.Loader)
        reflog = json.dumps(reflogdict['events'], sort_keys=True)
        return reflog

def compare_log (jsonreflog, jsontestlog, failedeventtypes={}):
    reflog = json.loads(jsonreflog)
    reflen = len(reflog)
    testlog = json.loads(jsontestlog)
    errors = 0
    for idx in range(0, reflen):
        if reflog[idx] != testlog[idx]:
            errors += 1
            failedeventtypes[reflog[idx]['EventType']] = True

    return (reflen, errors, failedeventtypes)

def compare_dir (dirname):
    binarylogs = glob.glob(dirname + '/raw/*.bin')
    failedeventtypes = {}
    etotal=0
    evttotal=0
    print("Eventlog parsing failure summary")
    print()
    print("+------------------------------+-------+-------+------+")
    print("|    log file                  | #Evts | #Fail | Pct. |")
    print("+------------------------------+-------+-------+------+")
    for binarylog in binarylogs:
        logname = os.path.basename(binarylog)
        try:
            yamllog = dirname + '/yaml/fixed/' + logname.replace('.bin', '.yaml')
            jsonreflog  = yaml2json(yamllog)
        except:
            # skip this because there is no reference log
            continue

        try:
            jsontestlog = binary2json(binarylog)
        except:
            # declare this parse failed
            reflog = json.load(jsonreflog)
            reflen = len(reflog)
            e = len(reflog)

        try:
            [reflen, e, failedeventtypes] = compare_log(jsonreflog, jsontestlog, failedeventtypes)
        except:
            reflog = json.load(jsonreflog)
            reflen = len(reflog)
            e = len(reflog)

        etotal+= e
        evttotal += reflen
        print("|%-30.30s|%7d|%7d|%5.2f%%|"%(logname, reflen, e, 100.0*e/reflen))

    print("+------------------------------+-------+-------+------+")
    print("|     Totals:                  |%7d|%7d|%5.2f%%|"%(evttotal, etotal, 100.0*etotal/evttotal))
    print("+------------------------------+-------+-------+------+")

    if etotal > 0:
        print()
        print("Failed event types")
        print("------------------")
        for key in failedeventtypes.keys():
            print("%-20s"%(key))
    else:
        print()
        print("SUCCESS")

    exit(etotal)
        
main()
