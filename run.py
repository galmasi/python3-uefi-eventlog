#!/usr/bin/env python3

import eventlog
import json

fp = open ('testlogs/css-flex14vm4-bootlog.binary', 'rb')

buffer = fp.read()
idx=0

log = eventlog.EventLog(buffer, len(buffer))

print(log)

#print(str(log.evtlist))

#print(log.toJson())
