#!/bin/bash


# $1 == the binary event log we want tested

export testcmd='eventlog2json.py'
export refcmd='tpm2_eventlog'

# ###################################
# reference log list of events: invoke tpm2-tools
# ###################################

function reflog() {
    local binarylog=${1}
    eval "${refcmd}  --eventlog-version=2 ${binarylog} | yq --sort-keys '.events'"
}

# ###################################
# run the python event log parser for the list of events
# ###################################

function testlog() {
    local binarylog=${1}
    eval "${testcmd} -f ${binarylog} | jq --sort-keys ."
}

# ###################################
# count the number of events in the log
# ###################################

function eventcounter() {
    local jsonlog=${1}
    cat ${jsonlog} | jq '. | length'
}

# ###################################
# given two JSON event logs, compare the JSONs for a particular event.
# ###################################

function compare_event() {
    local refjson=${1}
    local testjson=${2}
    local eventno=${3}
    local refevent=$(mktemp)
    local testevent=$(mktemp)
    cat ${refjson} | jq -r ".[${eventno}]" > ${refevent}
    cat ${testjson} | jq -r ".[${eventno}]" > ${testevent}
    diff ${refevent} ${testevent} > /dev/null 2>&1
    local retval=$?
    rm -f ${refevent} ${testevent}
    return ${retval}
}

# ###################################
# score the event log parser on a particular binary log
# ###################################

function evaluate_log() {
    local binarylog=${1}
    local refjson=$(mktemp)
    local testjson=$(mktemp)
    reflog ${binarylog} > ${refjson}
    testlog ${binarylog} > ${testjson}

    local eventcount=$(eventcounter ${testjson})
    local matchcount=0
    for eventno in $(seq 0 $eventcount)
    do
        if compare_event ${refjson} ${testjson} ${eventno}
        then
            matchcount=$((matchcount+1))
        fi
    done    
    rm -f ${refjson}
    rm -f ${testjson}
    echo "${matchcount} ${eventcount}"
    return 0
}


evaluate_log ${1} 
