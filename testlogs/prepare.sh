#!/bin/bash

export parsedir=parsed-tpm2-tools-5.5

# Initial preparation of parsed event logs using the Intel TPM2 tool kit.
# All Intel error messages are ignored. Only the parsed output is recorded.

export LD_LIBRARY_PATH=/usr/local/lib

for file in rhel/*.bin
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
    (cd ${dir}/${parsedir}/fixed && \
	 rm -f ${yamlname} && \
	 cat ../1stcut/${yamlname} | \
	     sed 's/"\(.*\)\\0"$/\1/' | \
	     sed 's/      "\(.*\)"$/      \1/' | \
	     sed 's/\\t/\t/g' | \
	     sed "s/\\\'/\'/g" | \
	     tee ${yamlname})
done

