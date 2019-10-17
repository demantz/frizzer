#!/usr/bin/env python3
#
# Frida-based fuzzer for blackbox fuzzing of network services.
#
# Author: Dennis Mantz (ERNW GmbH)
#         Birk Kauer   (ERNW GmbH)

from subprocess import check_output
import argparse
import frida
import socket
import ssl
import time
import shutil
import sys
import os

# frizzer modules:
from frizzer import log
from frizzer import project
from frizzer.coverage import parse_coverage, write_drcov_file


###
### FridaFuzzer Class 
###

class FridaFuzzer:
    """
    This class operates the fuzzing process.
    """

    def __init__(self, project):
        self.project       = project
        self.corpus        = None
        self.frida_session = None
        self.frida_script  = None
        self.modules       = None
        self.watched_modules = None
        self.accumulated_coverage = set()
        self.total_executions = 0
        self.start_time = None

        if not os.path.exists(project.coverage_dir):
            os.mkdir(project.coverage_dir)

    def getModuleMap(self):
        if self.frida_script == None:
            log.warn("getModuleMap: self.frida_script is None!")
            return None

        try:
            modulemap = self.frida_script.exports.makemaps()
        except frida.core.RPCException as e:
            log.info("RPCException: " + repr(e))
            return None

        self.modules = []
        for image in modulemap:
            idx  = image['id']
            path = image['path']
            base = int(image['base'], 0)
            end  = int(image['end'], 0)
            size = image['size']

            m = {
                    'id'    : idx,
                    'path'  : path,
                    'base'  : base,
                    'end'   : end,
                    'range' : range(base, end),
                    'size'  : size}

            self.modules.append(m)
        return self.modules

    def createModuleFilterList(self):
        """
        Creates the list of modules in which coverage information
        should be collected. This list is created by querying frida
        for the loaded modules and comparing them to the modules
        the user selected in the project settings.

        Must be called after frida was attached to the target and
        before any coverage is collected.
        """

        if self.modules == None:
            log.warn("filterModules: self.modules is None!")
            return False

        self.watched_modules = []
        for module in self.modules:
            if module["path"] in self.project.modules:
                self.watched_modules.append(module)

        if len(self.watched_modules) == 0:
            paths = "\n".join([m["path"] for m in self.modules])
            log.warn("filterModules: No module was selected! Possible choices:\n" + paths)
            return False
        else:
            paths = "\n".join([m["path"] for m in self.watched_modules])
            log.info("Filter coverage to only include the following modules:\n" + paths)
            return True


    def loadScript(self):
        scriptfile = os.path.join(os.path.dirname(__file__),'frida_script.js')
        log.info("Loading script: %s" % scriptfile)
        script_code = open(scriptfile, "r").read()
        script = self.frida_session.create_script(script_code)

        def on_message(message, data):
            if 'payload' in message.keys() and str(message['payload']) == "finished":
                pass
            else:
                log.info("on_message: " + str(message))
            #log.info("on_message: " + str(message['payload']))
            #log.info("on_message (data): " + str(data))

        script.on('message', on_message)
        script.load()
        script.exports.settarget(self.project.target_function)
        self.frida_script = script
        return script

    def sendFuzzPayload(self, payload):
        """
        Send fuzzing payload to target process via TCP socket
        """

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if self.project.ssl:
            s = ssl.wrap_socket(s)
        s.connect((self.project.host, self.project.port))

        try:
            s.sendall(payload)
            if self.project.recv_timeout:
                s.settimeout(self.project.recv_timeout)
                s.recv(1)
        except IOError as e:
            #log.debug("IOError: " + str(e))
            pass
        except EOFError as e:
            #log.debug("EOFError: " + str(e))
            pass
        s.close()

    def sendFuzzPayloadInProcess(self, payload):
        """
        Send fuzzing payload to target process by invoking the target function
        directly in frida
        """

        # Call function under fuzz:
        encoded = payload.hex()
        try:
            coverage_blob = self.frida_script.exports.fuzz(encoded)
            #log.info("sendFuzzPayloadInProcess: len=%d" % len(coverage_blob))
        except frida.core.RPCException as e:
            log.info("RPCException: " + repr(e))
            log.info("CRASH?")

    def getCoverageOfPayload(self, payload, timeout=0.1, retry=5):
        """
        Sends of the payload and checks the returned coverage.

        Important:
            Frida appears to have a bug sometimes in collecting traces with the stalker.. no idea how to fix this yet.. hence we do a retry. This can however screw up the replay functionality and should be fixed in the future.

        Arguments:
            payload {[type]} -- [description]

        Keyword Arguments:
            timeout {float} -- [description] (default: {0.1})
            retry {int} -- [description] (default: {5})

        Returns:
            [type] -- [description]
        """
        cnt = 0
        while cnt <= retry:
            try:
                if self.project.fuzz_in_process:
                    self.sendFuzzPayloadInProcess(payload)
                else:
                    self.sendFuzzPayload(payload)

                start = time.time()
                cov = None
                while (cov == None or len(cov) == 0) and (time.time()-start) < timeout:
                    cov = self.frida_script.exports.getcoverage()

                if cov != None and len(cov) > 0:
                    break

                cnt += 1

                if cov == None or len(cov) == 0:
                    log.info("getCoverageOfPayload: got nothing!")
                    return set()
            except frida.InvalidOperationError as e:
                log.warning("Error communicating with the frida script: %s" % str(e))
                self.detach()
                time.sleep(30)
                self.attach()

        return parse_coverage(cov, self.watched_modules)


    def buildCorpus(self):
        log.info("Initializing Corpus...")

        # Resetting Corpus to avoid at restart to have with ASLR more blocks than needed
        self.accumulated_coverage = set()

        corpus = [self.project.corpus_dir + "/" + x for x in os.listdir(self.project.corpus_dir)]
        corpus.sort()
        #log.debug("Corpus: " + str(corpus))

        if len(corpus) == 0:
            log.warn("Corpus is empty, please add files/directories with 'add'")
            return False

        for infile in corpus:
            fuzz_pkt = open(infile, "rb").read()
            coverage_last = None
            for i in range(5):
                t = time.strftime("%Y-%m-%d %H:%M:%S")
                log.update(t + " [iteration=%d] %s" % (i, infile))

                # send packet to target
                coverage = self.getCoverageOfPayload(fuzz_pkt)
                if coverage == None or len(coverage) == 0:
                    log.warn("No coverage was returned! you might want to delete %s from corpus if it happens more often" % infile)

                #log.info("Iteration=%d  covlen=%d file=%s" % (i, len(coverage), infile))

                if coverage_last != None and coverage_last != coverage:
                    log.warn(t + " [iteration=%d] Inconsistent coverage for %s!" % (i, infile))
                    #log.info("diff a-b:" + " ".join([str(x) for x in coverage_last.difference(coverage)]))
                    #log.info("diff b-a:" + " ".join([str(x) for x in coverage.difference(coverage_last)]))

                coverage_last = coverage
                # Accumulate coverage:
                self.accumulated_coverage = self.accumulated_coverage.union(coverage_last)

            write_drcov_file(self.modules, coverage_last,
                                     self.project.coverage_dir + "/" + infile.split("/")[-1])

        log.finish_update("Using %d input files which cover a total of %d basic blocks!" % (
                         len(corpus), len(self.accumulated_coverage)))
        self.corpus = corpus
        return True

    def doIteration(self, seed=None, corpus=None):
        if seed == None:
            seed = self.project.seed
        if corpus == None:
            corpus = self.corpus

        start_time = time.time()
        for pkt_file in corpus:
            log.update("[seed=%d] " % seed + time.strftime("%Y-%m-%d %H:%M:%S") + " %s" % pkt_file)
            #log.info(time.strftime("%Y-%m-%d %H:%M:%S") + " %s" % pkt_file)
            fuzz_pkt = check_output(["radamsa", "-s", str(seed), pkt_file])

            # Writing History file for replaying
            open(self.project.project_dir + "/frida_fuzzer.history", "a").write(str(pkt_file) + "|" + str(seed) + "\n")

            try:
                coverage = self.getCoverageOfPayload(fuzz_pkt)
            except (frida.TransportError, frida.InvalidOperationError) as e:
                log.warn("doIteration: Got a frida error: " + str(e))
                log.info("Current iteration: " + time.strftime("%Y-%m-%d %H:%M:%S") +
                         " [seed=%d] [file=%s]" % (seed, pkt_file))
                crash_file = self.project.crash_dir + time.strftime("/%Y%m%d_%H%M%S_crash")
                with open(crash_file + "_" + self.project.pid, "wb") as f:
                    f.write(fuzz_pkt)
                log.info("Payload is written to " + crash_file)
                self.project.crashes += 1
                return False

            if coverage == None:
                log.warn("No coverage was generated for [%d] %s!" % (seed, pkt_file))
                continue

            if not coverage.issubset(self.accumulated_coverage):
                # New basic blocks covered!
                log.info("Found new path: [%d] %s" % (seed, pkt_file))
                newfile = open(self.project.corpus_dir + "/" + str(seed) + "_" + pkt_file.split("/")[-1], "wb")
                newfile.write(fuzz_pkt)
                newfile.close()

                cov_file = self.project.coverage_dir + "/" + pkt_file.split("/")[-1]
                write_drcov_file(self.modules, coverage, cov_file)
                write_drcov_file(self.modules, coverage.difference(self.accumulated_coverage),
                                         cov_file + "_diff")

                self.project.last_new_path = seed
                self.accumulated_coverage = self.accumulated_coverage.union(coverage)

            self.total_executions += 1

        end_time = time.time()
        speed = len(corpus) / (end_time-start_time)
        avg_speed = self.total_executions / (end_time-self.start_time)

        log.finish_update("[seed=%d] speed=[%3d exec/sec (avg: %d)] coverage=[%d bblocks] corpus=[%d files] "
                         "last new path: [%d] crashes: [%d]" % (
                         seed, speed, avg_speed, len(self.accumulated_coverage), len(corpus),
                         self.project.last_new_path, self.project.crashes))
        return True

    def doReplay(self):
        """
        This function replays the last Session. This function will later implement also probes to test when the process is crashing
        """
        log.info("Starting the full Replay")
        with open(self.project.project_dir + "/frida_fuzzer.history") as fp:
            for line in fp:
                pkt_file, seed = line.split("|")
                try:
                    fuzz_pkt = check_output(["radamsa", "-s", str(seed.strip()), pkt_file])
                    if self.project.debug:
                        open(self.project.debug_dir + "/history", "a").write("file: {} seed: {} \n{}\n".format(
                            pkt_file,
                            seed,
                            fuzz_pkt,
                            ))
                    coverage = self.getCoverageOfPayload(fuzz_pkt)
                    log.info("Current iteration: " + time.strftime("%Y-%m-%d %H:%M:%S") +
                                " [seed=%d] [file=%s]" % (int(seed.strip()), pkt_file))
                except (frida.TransportError, frida.InvalidOperationError) as e:
                    log.success("doReplay: Got a frida error: " + str(e))
                    log.success("Current iteration: " + time.strftime("%Y-%m-%d %H:%M:%S") +
                                " [seed=%d] [file=%s]" % (int(seed.strip()), pkt_file))
                    log.success("Server Crashed! Lets narrow it down")
                    #crash_file = self.crash_dir + time.strftime("/%Y%m%d_%H%M%S_crash")
                    #with open(crash_file, "wb") as f:
                    #    f.write(fuzz_pkt)
                    #log.info("Payload is written to " + crash_file)
                    return False

                if coverage == None:
                    log.warn("No coverage was generated for [%d] %s!" % (seed, pkt_file))
        log.info("Sending Empty Package to verify the crashing server")
        try:
            coverage = self.getCoverageOfPayload(b'FOOBAR')
        except (frida.TransportError, frida.InvalidOperationError) as e:
            log.success("Server Crashed! Lets narrow it down")
            # TODO
            # Rabbit Mode here

        log.warning("History did not crash the Server! Might be due to some race conditions.")
        return False

    def doMinimize(self):
        """
        This Function will minimize the current Corpus
        """
        log.info("Minimizing Corpus...")
        # Reset the accumulated coverage
        self.accumulated_coverage = set()

        corpus = [self.project.corpus_dir + "/" + x for x in os.listdir(self.project.corpus_dir)]
        corpus.sort()

        if len(corpus) == 0:
            log.warn("Corpus is empty, please specify an input directory with --indir")
            return False

        for infile in corpus:
            fuzz_pkt = open(infile, "rb").read()
            coverage_last = None
            cov_cnt = 0
            tmp_accu_cov = set()
            for i in range(5):
                t = time.strftime("%Y-%m-%d %H:%M:%S")
                log.update(t + " [iteration=%d] %s" % (i, infile))

                # send packet to target
                coverage = self.getCoverageOfPayload(fuzz_pkt)
                if coverage == None or len(coverage) == 0:
                    cov_cnt += 1

                coverage_last = coverage
                # Accumulate coverage:
                tmp_accu_cov = tmp_accu_cov.union(coverage_last)

            if cov_cnt >= 4:
                if os.path.exists(infile):
                    log.warn("Moving %s from corpus since the returned coverage was always 0" % infile)
                    #TODO
                    backup_file = self.project.corpus_trash_dir + "/" + infile.split("/")[-1]
                    shutil.move(infile, backup_file)


            if not tmp_accu_cov.issubset(self.accumulated_coverage):
                # New Paths found. Add it to the overall coverage
                log.success("File: %s looks good for the corpus! Keeping it" % infile)
                self.accumulated_coverage = self.accumulated_coverage.union(coverage_last)
                write_drcov_file(self.modules, coverage_last,
                                     self.project.coverage_dir + "/" + infile.split("/")[-1])
            else:
                # No new paths found with current file... better delete it ;-)
                if os.path.exists(infile):
                    log.warn("Deleting %s from corpus since there was no new coverage in it" % infile)
                    os.remove(infile)

        log.finish_update("Using %d input files which cover a total of %d basic blocks!" % (
                         len(corpus), len(self.accumulated_coverage)))
        self.corpus = corpus
        return True

    def fuzzerLoop(self):
        self.getModuleMap()
        try:
            self.start_time = time.time()
            self.total_executions = 0
            while True:
                if not self.doIteration():
                    log.info("stopping fuzzer loop")
                    return False
                self.corpus = [self.project.corpus_dir + "/" + f for f in os.listdir(self.project.corpus_dir)]
                self.corpus.sort()
                self.project.seed += 1
                self.project.saveState()
        except KeyboardInterrupt:
            log.info("Interrupted by user..")

    def attach(self):
        if self.project.pid != None:
            target_process = self.project.pid
        elif self.project.process_name != None:
            target_process = self.project.process_name
        else:
            log.warn("No process specified with 'process_name' or 'pid'!")
            return False

        if self.project.remote_frida:
            self.frida_session = frida.get_remote_device().attach(target_process)
        else:
            self.frida_session = frida.attach(target_process)
        self.loadScript()
        pid = self.frida_script.exports.getpid()
        log.info("Attached to pid %d!" % pid)
        self.project.pid = pid

        # Query the loaded modules from the target
        self.getModuleMap()

        # ... and create the module filter list
        self.createModuleFilterList()
        return True

    def detach(self):
        try:
            self.frida_script.unload()
        except frida.InvalidOperationError as e:
            log.warn("Could not unload frida script: " + str(e))

        self.frida_session.detach()


###
### frizzer sub functions
### (init, add, fuzz, minimize, ...)
###

def init(args):
    if os.path.exists(args.project):
        log.warn("Project '%s' already exists!" % args.project)
        return
    log.info("Creating project '%s'!" % args.project)
    if not project.createProject(args.project):
        log.warn("Could not create project!")


def add(args):
    infiles = []
    for path in args.input:
        if not os.path.exists(path):
            log.warn("File or directory '%s' does not exist!" % path)
            return
        if os.path.isdir(path):
            infiles.extend([path + "/" + x for x in os.listdir(path)])
        else:
            infiles.append(path)

    corpus_dir = project.getInstance().corpus_dir
    for inFile in infiles:
        if not os.path.exists(corpus_dir + "/" + inFile.split("/")[-1]):
            log.info("Copying '%s' to corpus directory: " % inFile)
            shutil.copy2(inFile, corpus_dir)


def fuzz(args, fuzzer):
    #TODO (maybe? save the old history file.. do we need this?)
    #    history_file = self.project_dir + "/frida_fuzzer.history"
    #    if os.path.exists(history_file):
    #        backup_file = self.project_dir + time.strftime("/%Y%m%d_%H%M%S_frida_fuzzer.history")
    #        shutil.move(history_file, backup_file)
    #        log.info("Found old history file. Moving it to %s" % backup_file)

    if fuzzer.buildCorpus():
        log.debug("Corpus: " + str(fuzzer.corpus))
        fuzzer.fuzzerLoop()


def replay(args, fuzzer):
    log.info("Replay Mode!")
    fuzzer.doReplay()


def minimize(args, fuzzer):
    # Create Fuzzer and attach to target
    fuzzer = FridaFuzzer(project.getInstance())
    if not fuzzer.attach():
        return

    if fuzzer.doMinimize():
        log.info("Minimized the Corpus. Start again without the minimizing option!")
    else:
        log.warn("Failed to minimize the corpus!")


###
### Argument Parsing
###

def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    # Add subcommands
    parser_init     = subparsers.add_parser('init')
    parser_add      = subparsers.add_parser('add')
    parser_fuzz     = subparsers.add_parser('fuzz')
    parser_replay   = subparsers.add_parser('replay')
    parser_minimize = subparsers.add_parser('minimize')

    # Assign functions to subcommands
    parser_init.set_defaults(func=init)
    parser_add.set_defaults(func=add)
    parser_fuzz.set_defaults(func=fuzz)
    parser_replay.set_defaults(func=replay)
    parser_minimize.set_defaults(func=minimize)

    # Add general options
    for p in [parser_init, parser_add, parser_fuzz, parser_replay, parser_minimize]:
        p.add_argument("--verbose", "-v", action='store_true', help="Change log level to 'debug'")
        p.add_argument("--debug", action='store_true', help="Verbose Debugging in a file (every Request)")

    # Add subcommand specific parser options:
    for p in [parser_add, parser_fuzz, parser_replay, parser_minimize]:
        p.add_argument("--project", "-p", help="Project directory.")

    for p in [parser_fuzz, parser_replay, parser_minimize]:
        p.add_argument("--pid", help="Process ID or name of target program")
        p.add_argument("--seed", "-s", help="Seed for radamsa", type=int)
        p.add_argument("--function", "-f", help="Function to fuzz and over which the coverage is calculated")

    parser_init.add_argument("project", help="Project name / directory which will be created)")
    parser_add.add_argument("input", nargs="*", help="Input files and directories that will be added to the corpus")

    # Parse arguments
    args = parser.parse_args()

    if args.verbose:
        log.log_level = 3
    if args.project == None:
        log.warn("Please specify a project directory name with --project/-p")
        sys.exit(-1)

    return args


def main():
    args = parse_args()

    if args.command != "init":
        # Load project
        if not project.loadProject(args.project):
            log.warn("Error: Could not load project '%s'!" % args.project)
            return

    if args.command in ["fuzz", "replay", "minimize"]:
        # Create Fuzzer and attach to target
        fuzzer = FridaFuzzer(project.getInstance())
        if not fuzzer.attach():
            return

        # Invoke subcommand function with instantiated fuzzer
        args.func(args, fuzzer)

        log.info("Detach Fuzzer ...")
        fuzzer.detach()

    else:
        # Invoke subcommand function
        args.func(args)

    log.info("Done")
    return


if __name__ == "__main__":
    main()
