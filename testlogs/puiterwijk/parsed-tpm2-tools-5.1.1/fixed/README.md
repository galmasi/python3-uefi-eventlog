Fixes applied manually:

Event 36, partitions are completely messed up when parsed by
tpm2-tools. Substituted correct partition listing as parsed by python
code.

Event 38, device path parsed by tpm2-tools is empty. python code
substitutes hex output for device path when it's unparseable.

