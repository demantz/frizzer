Frizzer
=======

A coverage-guided blackbox fuzzer based on the Frida instrumentation framework.


Idea
----

This fuzzer is meant to be quick and relatively easy to set up in scenarios
where no source code is available for a network service. Via Frida it is
possible to retrieve coverage from uninstrumented binaries. Therefore, even
though the fuzzer is not fast or efficient it can still be beneficial during
assessments with restricted time frames.

The fuzzer is written in Python 3 and runs under Linux. However, the fuzzed
application does not necessarily have to run on the same system as long as
Frida is also available for the respective system. The fuzzer can remotely
connect to the Frida instance which runs on the target system.

Currently the fuzzer expects a target which communicates via TCP (plain or TLS)
and is already running. The fuzzer won't start (or restart) the service but
only fuzz it until it crashes.

As the fuzzer is not very efficient it is necessary to restrict the coverage
tracking to the interesting part of the target service. The basic idea is that
the fuzzer will only track coverage during the execution of the main network
protocol handler (i.e. a function which handles the incoming TCP payloads) of
the target service. The address of this function needs to be found via reverse
engineering and has to be provided to the fuzzer.


Installation
------------

The fuzzer is written in Python 3 and depends on the python module `frida-tools`
and `toml`. It is recommended to set up a Python virtual environment:

    $ git clone https://cis.ernw.net/dmantz/frida-fuzzer
    $ cd frida-fuzzer
    $ virtualenv3 venv
    $ source venv/bin/activate
    $ pip install -e .
    $ frizzer --help

The fuzzer also needs radamsa () to be available on the system. For Debian
based systems it can be installed with the following commands:

    $ sudo apt update && sudo apt install gcc git make wget
    $ git clone https://gitlab.com/akihe/radamsa.git
    $ cd radamsa
    $ make
    $ sudo make install



Usage
-----

First it is necessary to find the main protocol handler function of the target
service. It is important that this function is called exactly once for every
TCP connection that the fuzzer initiates. For example, the `picohttpparser.c`
file (`tests/picohttpparser/picohttpparser.c`) has a function
`parse_request(...)` which matches the above mentioned requirements. Once the
address of this function has been found via reverse engineering, the fuzzing
can be configured.

The first step is to create a new project (this command will create a new
project directory `fuzzproject1`):

    $ frizzer init fuzzproject1

The project directory contains the following files/folders:
- config:  Config file for the fuzzer
- corpus:  Current fuzzing corpus (contains the payloads)
- crashes: Contains all payloads that have led to a crash

After creating the project, the config file has to be edited. The generated file
looks like this:

    [fuzzer]
    log_level       = 3 # debug
    debug_mode      = false

    [target]
    process_name    = "myprocess"
    function        = 0x123456
    host            = "localhost"
    port            = 7777
    ssl             = false
    remote_frida    = false
    recv_timeout    = 0.1
    fuzz_in_process = false
    modules = [
            "/home/dennis/tools/frida-fuzzer/tests/simple_binary/test",
        ]

- Change the `process_name` parameter to the name of the process which should
  be fuzzed. The fuzzer will resolve the name to a PID (make sure only one
  instance of the service is running!) and attach to it via Frida.
- Change the `function` parameter to the address of the protocol handler
  function. The fuzzer will hook this function via Frida and start the Frida
  Stalker to record which basic blocks are executed. The Stalker is stopped and
  the coverage processed as soon as the protocol handler function returns.
- Change the `host` and `port` parameters to point to the service that shall be
  fuzzed. The fuzzer will establish a TCP connection for every new payload.
  When setting `ssl` to `true` the fuzzer will establish a TLS connection and
  send the payload through the TLS socket instead.
- Change the `modules` parameter so that it contains a list of all modules for
  which the Stalker should track coverage (i.e. the main executable and
  potentially interesting .so files). The modules have to be given with absolute
  path! Do not include shared libraries in which you are not interested (e.g.
  the libc or other standard libs) as this will generate a lot of coverage
  data and render the fuzzing process inefficient.

Finally, add one or more initial payload files to the project:

    $ frizzer add -p fuzzproject1 myinitialfiles

In this command, `-p fuzzproject1` specifies the project directory and
`myinitialfiles` is a directory which contains the payload files that shall
be copied over to the corpus directory. If the protocol format is completely
unknown just start with a single file containing a single 'A' and let radamsa
and the coverage tracking figure out the protocol format. This may be too
inefficient and it is recommended to continue reverse engineering as soon as
the fuzzer is running. New payload files can be added at any time with the
`add` subcommand of frizzer.

Now the fuzzer can be started with the following command (note that the service
needs to be running already!):

    $ frizzer fuzz -p fuzzproject1

The output should look like this:

    [+] Project: {'fuzzer': {'log_level': 3, 'debug_mode': False}, 'target': {'process_name': 'test', 'function': 4198998, 'host': 'localhost', 'port': 7777, 'remote_frida': False, 'fuzz_in_process': False, 'modules': ['/home/dennis/frida-fuzzer/tests/simple_binary/test']}}
    [+] Loading script: /home/dennis/frida-fuzzer/frizzer/frida_script.js
    [+] Attached to pid 502277!
    [+] Filter coverage to only include the following modules:
    /home/dennis/tools/frida-fuzzer/tests/simple_binary/test
    [+] Initializing Corpus...
    [*] 2020-06-24 11:34:02 [iteration=1] tmpprojdir/corpus/1
    [!] 2020-06-24 11:34:02 [iteration=1] Inconsistent coverage for tmpprojdir/corpus/1!
    [*] 2020-06-24 11:34:02 [iteration=1] tmpprojdir/corpus/2
    [!] 2020-06-24 11:34:02 [iteration=1] Inconsistent coverage for tmpprojdir/corpus/2!
    [*] Using 4 input files which cover a total of 10 basic blocks!
    [D] Corpus: ['tmpprojdir/corpus/1', 'tmpprojdir/corpus/2', 'tmpprojdir/corpus/3', 'tmpprojdir/corpus/4']
    [*] [seed=0] speed=[ 67 exec/sec (avg: 67)] coverage=[10 bblocks] corpus=[4 files] last new path: [-1] crashes: [0]
    [*] [seed=1] speed=[ 87 exec/sec (avg: 76)] coverage=[10 bblocks] corpus=[4 files] last new path: [-1] crashes: [0]
    [*] [seed=2] speed=[ 85 exec/sec (avg: 79)] coverage=[10 bblocks] corpus=[4 files] last new path: [-1] crashes: [0]
    [*] [seed=3] speed=[ 90 exec/sec (avg: 81)] coverage=[10 bblocks] corpus=[4 files] last new path: [-1] crashes: [0]
    [*] [seed=4] speed=[ 91 exec/sec (avg: 83)] coverage=[10 bblocks] corpus=[4 files] last new path: [-1] crashes: [0]
    [*] [seed=5] 2020-06-24 11:34:02 tmpprojdir/corpus/3
    [+] Found new path: [5] tmpprojdir/corpus/3
    [*] [seed=5] speed=[ 86 exec/sec (avg: 83)] coverage=[12 bblocks] corpus=[4 files] last new path: [5] crashes: [0]
    [*] [seed=6] speed=[ 88 exec/sec (avg: 84)] coverage=[12 bblocks] corpus=[5 files] last new path: [5] crashes: [0]
    ...

The `seed` value reveres to the seed which is passed to radamsa. By default the
seed will start at 0 and is increased in each round. Each round will produce
new payloads for all files which are currently in the `corpus` directory. This
is done by passing each file and the current seed to radamsa. The resulting new
payloads are sent to the target. If the coverage for a specific payload
contains new basic blocks (i.e. a `new path`), the payload is added to the
corpus.

Also have a look at the test cases to get an idea on how to use the fuzzer!

