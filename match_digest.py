#!/usr/bin/env python3

import eventlog
import argparse

def parser_main():
    parser = argparse.ArgumentParser(
        description="List/Match the digest[s]"
    )
    parser.add_argument(
        "-f",
        "--file",
        help="measured boot log binary file",
    )
    parser.add_argument(
        "-d",
        "--digest",
        help="digest value",
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

    if args.event not in eventlog.Event.__members__:
        print('Invalid event type')
        return

    algid = int(args.algid)
    if algid not in eventlog.EfiEventDigest.hashalgmap:
        print ('Invalid hash algorithm id.')
        return

    log=eventlog.EventLog(buffer, len(buffer))

    if not args.digest:
        if args.pcr:
            dg_list = eventlog.get_digests(log, args.event, hash_algid=algid, pcr_index=int(args.pcr))
        else:
            dg_list = eventlog.get_digests(log, args.event, hash_algid=algid)
        print(dg_list) 
    else:
        if args.pcr:
            matched = eventlog.match_digest(log, args.event, algid, args.digest, pcr_index=int(args.pcr))
        else:
            matched = eventlog.match_digest(log, args.event, algid, args.digest, algid)
        if matched:
            print('Digest matched!')
        else:
            print('Digest does not match!')
           
if __name__ == "__main__":
    main()
