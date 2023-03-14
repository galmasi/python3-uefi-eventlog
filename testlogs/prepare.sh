#!/bin/bash

export parsedir=parsed-tpm2-tools-5.1.1

# Initial preparation of parsed event logs using the Intel TPM2 tool kit.
# All Intel error messages are ignored. Only the parsed output is recorded.

export LD_LIBRARY_PATH=/usr/local/lib

for file in */*.bin
do
    fname=$(basename ${file})
    yamlname=${fname/.bin/.yml}
    dir=$(dirname ${file})
    echo $fname
    mkdir -p ${dir}/${parsedir}/1stcut
    tpm2_eventlog --eventlog-version=2 ${file} > ${dir}/${parsedir}/1stcut/${yamlname}
    exitcode=$?
    echo "${yamlname} ${exitcode}"
    mkdir -p ${dir}/${parsedir}/fixed
    (cd ${dir}/${parsedir}/fixed && ln -sf ../1stcut/${yamlname} .)
done

