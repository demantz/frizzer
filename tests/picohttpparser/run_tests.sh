#!/bin/bash

# Expected bahavior:
# Find 175 bblocks at seed 100 (31 files)
# Average Speed: between 50 and 55
# [+] [seed=100]: speed=[59 exec/sec (avg: 52)] coverage=[175 bblocks] corpus=[31 files] last new path: [94] crashes: [0]
# [+] [seed=1700]: speed=[35 exec/sec (avg: 41)] coverage=[188 bblocks] corpus=[42 files] last new path: [1639] crashes: [0]

rm -rf tmpprojdir

# old:
# frizzer --project tmpprojdir --indir indir -f 0x401276 -t 7777 -p test -m /home/dennis/tools/frida-fuzzer/tests/picohttpparser/test

# new:
frizzer init tmpprojdir
cat > tmpprojdir/config <<EOF
[fuzzer]
log_level       = 3 # debug
debug_mode      = false

[target]
process_name    = "test"
function        = 0x401276
host            = "localhost"
port            = 7777
remote_frida    = false
fuzz_in_process = false
modules = [
        "/home/dennis/tools/frida-fuzzer/tests/picohttpparser/test",
    ]
EOF

frizzer add -p tmpprojdir indir
frizzer fuzz -p tmpprojdir
