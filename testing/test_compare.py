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
#    parser.add_argument(
#        "-r",
#        "--raw",
#        help="binary event log file"
#    )
#    parser.add_argument(
#        "-y",
#        "--yaml",
#        help="yaml reference file"
#    )


    args = parser.parse_args()
    compare_dir(args.dir)
#    assert args.raw, "binary file argument is required"
#    assert args.yaml, "yaml file argument is required"

#    jsonreflog = yaml2json(args.yaml)
#    jsontestlog = binary2json(args.raw)
#    print(compare_log (jsonreflog, jsontestlog))



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
    testlog = json.loads(jsontestlog)
    reflen = len(reflog)
    testlen = len(testlog)
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
            yamllog = dirname + '/yaml/' + logname.replace('.bin', '.yaml')
            jsontestlog = binary2json(binarylog)
            jsonreflog  = yaml2json(yamllog)
            [t, e, failedeventtypes] = compare_log(jsonreflog, jsontestlog, failedeventtypes)
            etotal+= e
            evttotal += t
            print("|%-30.30s|%7d|%7d|%5.2f%%|"%(logname, t, e, 100.0*e/t))
        except:
            pass
    print("+------------------------------+-------+-------+------+")
    print("|     Totals:                  |%7d|%7d|%5.2f%%|"%(evttotal, etotal, 100.0*etotal/evttotal))
    print("+------------------------------+-------+-------+------+")

    print()
    print("Failed event types")
    print("------------------")
    for key in failedeventtypes.keys():
        print("%-20s"%(key))
    
main()
