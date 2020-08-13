#!/bin/bash

# Expected bahavior:
# Find new paths at seeds: 5, 111, 135, ...
# Find crash at seed 17??
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
fuzz_in_process = true
recv_timeout    = 0.1

[target]
process_pid     = $test_pid
function        = "handleClient"    # function can either be a symbol name or an absolute address
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
