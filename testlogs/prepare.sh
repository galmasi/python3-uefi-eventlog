#!/bin/bash

# Initial preparation of parsed event logs using the Intel TPM2 tool kit.
# All Intel error messages are ignored. Only the parsed output is recorded.

export LD_LIBRARY_PATH=/usr/local/lib

for file in */*.bin
do
    fname=$(basename ${file})
    yamlname=${fname/.bin/.yml}
    dir=$(dirname ${file})
    echo $fname
    mkdir -p ${dir}/parsed/1stcut
    tpm2_eventlog --eventlog-version=2 ${file} > ${dir}/parsed/1stcut/${yamlname}
    exitcode=$?
    echo "${yamlname} ${exitcode}"
    mkdir -p ${dir}/parsed/fixed
    (cd ${dir}/parsed/fixed && ln -sf ../1stcut/${yamlname} .)
done

