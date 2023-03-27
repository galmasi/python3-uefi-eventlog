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
        description ="run validation on binary logs"
    )
    parser.add_argument(
        '-d',
        '--dir',
        help='directory where raw and yaml logs are kept')

    args = parser.parse_args()
    compare_dir(args.dir)

def compare_dir (dirname):
    binarylogs = glob.glob(dirname + '/*/*.bin')
    print()
    print("+------------------------------+-------+-------+-------+")
    print("|    log file                  | #Ign. | #Pass | #Fail |")
    print("+------------------------------+-------+-------+-------+")
    for binarylog in binarylogs:
        logname = os.path.basename(binarylog)
        with open (binarylog, 'rb') as fp:
            buffer = fp.read()
            try:
                testlog = eventlog.EventLog(buffer, len(buffer))
                [vac, pas, fail] = testlog.validate()
                print("|%-30.30s|%7d|%7d|%7d|"%(logname, len(vac), len(pas), len(fail)))
            except Exception as e:
                print('fail: %s'%(str(e)))
                pass
            
        #print("|%-30.30s|%7d|%7d|%6.2f%%|"%(logname, reflen, e, 100.0*e/reflen))

        #print("+------------------------------+-------+--------+------+")
    #print("|     Totals:                  |%7d|%7d|%6.2f%%|"%(evttotal, etotal, 100.0*etotal/evttotal))
    #print("+------------------------------+-------+--------+------+")

    #if etotal/evttotal > 0.01:
    #    print()
    #    print("Failed event types")
    #    print("------------------")
    #    for key in failedeventtypes.keys():
    #        print("%-20s"%(key))
    #    exit(1)
    #else:
    #    print()
    #    print("SUCCESS (error rate < 1%)")
    #    exit(0)
        
main()
