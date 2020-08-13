#!/bin/bash

# Expected bahavior:
# Find new paths at seeds: 5, 111, 135, ...
# Find crash at 1793  ( ~ 4 minutes )
# [*] [seed=1792] speed=[ 77 exec/sec (avg: 56)] coverage=[20 bblocks] corpus=[9 files] last new path: [1422] crashes: [0]
# [*] [seed=1793] 2020-08-11 12:53:53 tmpprojdir/corpus/1422_1290_111_5_3
# [!] doIteration: Got a frida error: the connection is closed
# [+] Current iteration: 2020-08-11 12:53:54 [seed=1793] [file=tmpprojdir/corpus/1422_1290_111_5_3]
# [+] Payload is written to tmpprojdir/crashes/20200811_125354_crash
# [+] stopping fuzzer loop
# [+] Detach Fuzzer ...
# [!] 'target'.detach: Could not unload frida script: script is destroyed
# [+] Done
# Average Speed: between 40 and 50

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
process_pid     = $test_pid
function        = "handleClient"
remote_frida    = false
frida_port      = 27042
modules = [
        "tests/simple_binary/test",
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
grep 'Found new path: \[135\] tmpprojdir/corpus/111_5_3' tmpprojdir/*.log
result=$?

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
