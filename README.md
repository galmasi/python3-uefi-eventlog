# python3-uefi-eventlog

A pure python library to parse and process UEFI measured boot logs.

## Purpose

Replace the external references to tpm2-tools in the Keylime project.

## Getting started

The only file currently needed is `eventlog/eventlog.py`. Absent a
packaging system (TBD) copy the file into your project and import
it. Then use it as below to produce JSON output:

```
    import eventlog

    ...

    with open (<name of binary event log file>, 'rb') as fp:
        buffer = fp.read()
        evlog = eventlog.EventLog(buffer, len(buffer))
        print(json.dumps(evlog, default=lambda o: o.toJson(), indent=4))

```

Note the use of a JSON "transformer" function -- every class in the
`eventlog` package implements this function. The design purpose is to
allow the eventlog parser to collect information into a custom class
hierarchy with data members corresponding to each event type as
defined by TCG, and then use the `toJson()` member function to create
JSON compatible output.

## Design principle

The library is designed to be a drop-in replacement in Keylime's event
log processing. The JSON output generated is identical to that
produced by `tpm2-tools/tpm2_eventlog`, with two exceptions:

* We did not see fit to reproduce certain `tpm2_eventlog` bugs just
  for compliance

* We improve slightly on the tpm2_eventlog output by additionally parsing
  UEFI device paths into human-readable format.

## Directory structure

* The event log parser itself is in the `eventlog` directory.

* Reference logs for testing are in the `testlog` directory. Each
  binary event log is accompanied by the YAML formatted output
  produced by `tpm2_eventlog`.

* Testing code and reference usage code are in the `testing` directory.

## Testing and CI

Testing of this repository is arranged against a known set of binary
event logs, comparing the output of the `eventlog` library against a
"known good" reference. Each run is scored by the number of events
where output diverges from the reference.

As reference, we use the *hand-corrected* `tpm2_eventlog` parsed text
output for the same binaries.

## Outstanding list of TODOs

* While the eventlog library is able to generate the TPM PCR outputs,
  that output is not being tested today. (TEST MISSING)

* There are only 5 event logs to test against (TEST MISSING). Need more.

* While the UEFI specification allows for partial self-consistency
  checks in the event log, those consistency checks are not yet
  correctly implemented (FEATURE MISSING)

* Only a subset of digest algorithms supported by the TCG
  specification is implemented; namely, `sha1`, `sha256`,
  `sha384`. This subset covers all event logs we have seen so far, but
  this also means that most likely there exists an event log somewhere
  that the python library cannot handle today (FEATURE MISSING)

* The `efivar` based enrichment feature is currently disabled and not
  tested (FEATURE MISSING).

* There is no support for packaging yet (FEATURE MISSING)

## Documentation and references:

* Reference documentation from the (Trusted Computing
  Group)[https://trustedcomputinggroup.org/resource/tpm-library-specification]:

  * Trusted Platform Module Library, Part 1 (commands), Part 2 (structures)
  * TCG Guidance on Integrity Measurements and Event Log Processing
  * TCG PC Client Platform Firmware Profile Specification

* (Intel TPM2 software)[https://github.com/tpm2-software]

* (IBM's TPM 2.0 TSS library)[https://sourceforge.net/projects/ibmtpm20tss/]

* Patrick Uiterwijk's (rust event parser library)[https://github.com/puiterwijk/uefi-eventlog-rs]
