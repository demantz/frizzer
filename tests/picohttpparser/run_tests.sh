#!/bin/bash

# Expected bahavior:
# Find 175 bblocks at seed 100 (31 files)
# Average Speed: between 50 and 55
# [+] [seed=100]: speed=[59 exec/sec (avg: 52)] coverage=[175 bblocks] corpus=[31 files] last new path: [94] crashes: [0]
# [+] [seed=1700]: speed=[35 exec/sec (avg: 41)] coverage=[188 bblocks] corpus=[42 files] last new path: [1639] crashes: [0]

# Enable job control for shell script (so we can use 'fg', etc)
set -m

exitfn () {
    trap SIGINT
    echo 'Interrupted by user!'
    kill $test_pid
    kill $frizzer_pid
    exit
}

trap "exitfn" INT            # Set up SIGINT trap to call function.

./test > /dev/null &
test_pid=$!

rm -rf tmpprojdir

# new:
frizzer init tmpprojdir
cat > tmpprojdir/config <<EOF
[fuzzer]
log_level       = 3 # debug
write_logfile   = true
debug_mode      = false
host            = "localhost"
port            = 7777
ssl             = false
udp             = false
fuzz_in_process = false
recv_timeout    = 0.1

[target]
process_name    = "test"
function        = 0x401276
remote_frida    = false
frida_port      = 27042
modules = [
        "tests/picohttpparser/test",
    ]
EOF

frizzer add -p tmpprojdir indir

# start frizzer in the background
frizzer fuzz -p tmpprojdir &
frizzer_pid=$!

# kill frizzer after 15 seconds
(sleep 15; kill -s INT $frizzer_pid)&

# get frizzer back in the foreground
fg frizzer

echo frizzer stopped!

# check if fuzzer worked correctly:
grep 'Found new path: \[41\] tmpprojdir/corpus/36_26_2_2' tmpprojdir/*.log
result=$?

echo "result: $result"

if [ $result -eq 0 ]; then
    echo "Test succeeded!"
    rm -rf tmpprojdir
else
    echo "Test failed!"
fi

# cleanup
kill $test_pid
trap SIGINT
exit $result
