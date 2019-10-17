#!/bin/bash

# Expected bahavior:
# Find new paths at seeds: 5, 111, 135, ...
# Find crash at seed 17??
# Average Speed: between 40 and 50

#make
#./test > /dev/null &

rm -rf tmpprojdir

# old:
# frizzer --project tmpprojdir --indir indir -f 0x401256 -t 7777 -p test -m /home/dennis/tools/frida-fuzzer/tests/simple_binary/test

# new:
frizzer init tmpprojdir
cat > tmpprojdir/config <<EOF
[fuzzer]
log_level       = 3 # debug
debug_mode      = false

[target]
process_name    = "test"
function        = 0x401256
host            = "localhost"
port            = 7777
remote_frida    = false
fuzz_in_process = false
modules = [
        "/home/dennis/tools/frida-fuzzer/tests/simple_binary/test",
    ]
EOF

frizzer add -p tmpprojdir indir
frizzer fuzz -p tmpprojdir


