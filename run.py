#!/usr/bin/env python3

import eventlog
import json


fp = open ('testlogs/css-flex14vm4-bootlog.binary', 'rb')
buffer = fp.read()
idx=0

log = eventlog.EventLog(buffer, len(buffer))


print(json.dumps(log, default=lambda o: o.toJson(), indent=4))

print('-----------------------')

if log.validate():
    print ("Log is valid")
else:
    print ("Log is invalid")

print('-----------------------')
    
#print(sorted(log.pcrs().items()))
