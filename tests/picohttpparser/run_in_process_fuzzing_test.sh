#!/bin/bash

# Not clear why this does not behave the same as without in-process fuzzing...

rm -rf tmpprojdir

# old:
# frizzer --project tmpprojdir --indir indir -f 0x401276 -p test -m /home/dennis/tools/frida-fuzzer/tests/picohttpparser/test --in-process

# new:
frizzer init tmpprojdir
cat > tmpprojdir/config <<EOF
[fuzzer]
log_level       = 3 # debug
debug_mode      = false

[target]
process_name    = "test"
function        = 0x401276
remote_frida    = false
fuzz_in_process = true
modules = [
        "/home/dennis/tools/frida-fuzzer/tests/picohttpparser/test",
    ]
EOF

frizzer add -p tmpprojdir indir
frizzer fuzz -p tmpprojdir

