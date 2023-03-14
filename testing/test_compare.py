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
        description ="compare event logs and test logs"
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
    binarylogs = glob.glob(dirname + '/*/*.bin')
    failedeventtypes = {}
    etotal=0
    evttotal=0
    print("Eventlog parsing failure summary")
    print()
    print("+------------------------------+-------+-------+-------+----")
    print("|    log file                  | #Evts | #Fail |  Pct. | msg.")
    print("+------------------------------+-------+-------+-------+----")
    for binarylog in binarylogs:
        logdir  = os.path.dirname(binarylog)
        logname = os.path.basename(binarylog)

        # step 1: read the reference log and interpret it as JSON
        try:
            yamllog = logdir + '/parsed/fixed/' + logname.replace('.bin', '.yml')
            jsonreflog  = yaml2json(yamllog)
            reflog = json.loads(jsonreflog)
            reflen = len(reflog)
        except Exception as e:
            etotal+= 1
            evttotal += 1
            print("|%-30.30s|%7d|%7d|%6.2f%%|reflog fail: %s"%(logname, 1, 1, 100.0, str(e)))
            continue

        # step 2: try the python log parser and translate to JSON
        try:
            jsontestlog = binary2json(binarylog)
        except Exception as e:
            e = len(reflog)
            etotal+= e
            evttotal += reflen
            print("|%-30.30s|%7d|%7d|%6.2f%%|testlog fail: %s"%(logname, reflen, e, 100.0*e/reflen, str(e)))
            continue

        # step 3: compare both JSON logs
        try:
            [reflen, e, failedeventtypes] = compare_log(jsonreflog, jsontestlog, failedeventtypes)
        except:
            e = len(reflog)

        etotal+= e
        evttotal += reflen
        print("|%-30.30s|%7d|%7d|%6.2f%%|"%(logname, reflen, e, 100.0*e/reflen))

    print("+------------------------------+-------+--------+------+")
    print("|     Totals:                  |%7d|%7d|%6.2f%%|"%(evttotal, etotal, 100.0*etotal/evttotal))
    print("+------------------------------+-------+--------+------+")

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
