#!/usr/bin/env python3

import eventlog
import argparse

def parser_main():
    parser = argparse.ArgumentParser(
        description="Get list of digests for a given event type"
    )
    parser.add_argument(
        "-f",
        "--file",
        help="measured boot log binary file",
    )
    parser.add_argument(
        "-e",
        "--event",
        help="event type",
    )
    parser.add_argument(
        "-a",
        "--algid",
        default="11",
        help="algorithm id",
    ) 
    parser.add_argument(
        "-p",
        "--pcr",
        help="pcr index",
    ) 
    return parser

def main():
    p = parser_main()
    args = p.parse_args()

    assert (args.file),"file is required"
    assert (args.event),"event type is required"

    with open (args.file, 'rb') as f:
        buffer = f.read()

    if not eventlog.eventtype_valid(args.event):
        print('Invalid event type')
        return

    if args.algid:
        algid = int(args.algid)
        if not eventlog.algid_valid(algid):
            print ('Invalid hash algorithm id.')
            return

    log=eventlog.EventLog(buffer, len(buffer))
    if args.pcr:
        dg_list = eventlog.get_digests(log, args.event, hash_algid=algid, pcr_index=int(args.pcr))
    else:
        dg_list = eventlog.get_digests(log, args.event, hash_algid=algid)
    print(dg_list) 
           
if __name__ == "__main__":
    main()
