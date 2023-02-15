#!/bin/bash

# ###################################
# This script runs a comparison of event handling between tpm2_eventlog and this repo.
# ###################################



export PATH=${PATH}:~/code/TPM2/tpm2-tools/tools/tpm2_eventlog
export PATH=${PATH}:`pwd`/testing

export PYTHONPATH=${PYTHONPATH}:`pwd`
export VERBOSE=${VERBOSE:-"no"}

# $1 == the binary event log we want tested

export testcmd='eventlog2json.py'

# ###################################
# reference log list of events: invoke tpm2-tools
# ###################################

function reflog() {
    local yamllog=${1}
    cat ${yamllog} | yq --sort-keys '.events'
}

# ###################################
# run the python event log parser for the list of events
# ###################################

function testlog() {
    local binarylog=${1}
    ${testcmd} -f ${binarylog} | jq --sort-keys .
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
    if ! diff ${refevent} ${testevent} > /dev/null 2>&1
    then
        if [[ ${VERBOSE} != "no" ]]
        then
            echo "Event ${eventno} type=$(cat ${testevent} | jq -r .EventType)"
            diff ${refevent} ${testevent}
        fi
        rm -f ${refevent} ${testevent}
        return 1
    fi
    rm -f ${refevent} ${testevent}
    return 0
}

# ###################################
# score the event log parser on a particular binary log
# ###################################

function evaluate_log() {
    local rawlog=${1}
    local yamllog=${2}
    local refjson=$(mktemp)
    local testjson=$(mktemp)

    reflog ${yamllog} > ${refjson}
    local eventcount=$(eventcounter ${refjson})
    if ! testlog ${rawlog} > ${testjson} 2>/dev/null
    then
        rm -f ${refjson}
        rm -f ${testjson}
        echo "${eventcount}"
        return 0
    fi
    
    local matchcount=0
    for eventno in $(seq 0 $((eventcount-1)))
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

# ###################################
# ###################################

function evaluate_logs() {
    local logdir=${1}
    set matchcount=0
    set eventcount=0
    set filecount=0
    echo   "+====================+==========+==========+==========+"
    echo   "| Files              |   Events |  Matches |  Rate    |"
    echo   "+====================+==========+==========+==========+"
    for rawlog in ${logdir}/raw/*.bin
    do
        local logname=$(basename ${rawlog} | sed "s/.bin\$//")
        local yamllog=${logdir}/yaml/${logname}.yaml
        local x=$(evaluate_log ${rawlog} ${yamllog})
        local x1=$(echo $x | tail -1 | awk '{ print $1 }')
        local x2=$(echo $x | tail -1 | awk '{ print $2 }')
        filecount=$((filecount+1))
        matchcount=$((matchcount + x1))
        eventcount=$((eventcount + x2))
        printf "|%20.20s|%10d|%10d|%10.2f|\n" ${logname} ${x2} ${x1} $((100*x1/x2))
    done
    echo   "+--------------------+----------+----------+----------+"
    printf "|  Total             |%10d|%10d|%10.2f|\n" \
           ${eventcount} ${matchcount} $((100*matchcount/eventcount))
    echo   "+--------------------+----------+----------+----------+"
}

evaluate_logs $1

#reflog testlogs/bootlog-5.0.0-rhel-20210423T133156Z_8b0347a.bin
