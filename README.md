# python3-uefi-eventlog

A pure python library to parse and process UEFI measured boot logs.

## Purpose

Replace the external references to tpm2-tools in the Keylime project.

## Design principle

The library is designed to be a drop-in replacement in Keylime's event
log processing. The JSON output generated is identical to that
produced by `tpm2-tools/tpm2_eventlog`, with two exceptions:

* We did not see fit to reproduce certain `tpm2_eventlog` bugs just
  for compliance

* We improve slightly on the tpm2_eventlog output by additionally parsing
  UEFI device paths into human-readable format.

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

* While the UEFI specification allows for partial self-consistency
  checks in the event log, those consistency checks are not yet
  correctly implemented.

* Only a subset of digest algorithms supported by the TCG
  specification is implemented; namely, `sha1`, `sha256`,
  `sha384`. This subset covers all event logs we have seen so far, but
  this also means that most likely there exists an event log somewhere
  that the python library cannot handle today.

## Documentation and references:

* Reference documentation from the Trusted Computing Group:
  * Trusted Platform Module Library, Part 1 (commands), Part 2 (structures)
  * TCG Guidance on Integrity Measurements and Event Log Processing
  * TCG PC Client Platform Firmware Profile Specification

https://trustedcomputinggroup.org/resource/tpm-library-specification/

* Intel TPM2 software

https://github.com/tpm2-software

* IBM's TPM 2.0 TSS library

https://sourceforge.net/projects/ibmtpm20tss/

* Patrick Uiterwijk's rust event parser library

https://github.com/puiterwijk/uefi-eventlog-rs
