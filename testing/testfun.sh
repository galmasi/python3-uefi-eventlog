#!/bin/bash


# $1 == the binary event log we want tested

# testcmd
export testcmd='./eventlog2json.py'

function eventnum() {
    local binarylog=${1}
    eval "${testcmd} -f ${binarylog} | jq '. | length'"
}

function testevent() {
    local binarylog=${1}
    local eventnum=${2}
    eval "${testcmd} -f ${binarylog} | jq --sort-keys '.[${eventnum}]'"
}

function refevent() {
    local binarylog=${1}
    local eventnum=${2}
    local refcmd=${3:-tpm2_tools}
    eval "${refcmd} --eventlog-version=2 ${binarylog} | yq --sort-keys '.events[${eventnum}]'"
}

function compare_event() {
    local binarylog=${1}
    local eventnum=${2}
    local f1=$(mktemp)
    local f2=$(mktemp)
    refevent ${binarylog} ${eventnum}  ~/code/TPM2/tpm2-tools/tools/tpm2_eventlog | jq 'del(.EventNum)' > ${f1}
    testevent ${binarylog} ${eventnum} > ${f2}
    diff ${f1} ${f2} 
    local retval=$?
    rm -f ${f1} ${f2}
    return ${retval}
}

function compare_log() {
    local binarylog=${1}
    local nevents=$(eventnum ${binarylog})
    for event in $(seq 0 $nevents)
    do
        echo "Diffing event ${event}"
        compare_event ${binarylog} ${event}
    done
}


compare_log ${1} 
