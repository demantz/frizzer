#!/usr/bin/env python3
#
# Frida-based fuzzer for blackbox fuzzing of network services.
#
# Author: Dennis Mantz (ERNW GmbH)
#         Birk Kauer   (ERNW GmbH)

from subprocess import check_output
import traceback
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
        self.project                 = project
        self.targets                 = project.targets
        self.active_target           = project.targets[0]   # Target which produced coverage most recently
        self.corpus                  = None
        self.accumulated_coverage    = set()
        self.total_executions        = 0
        self.start_time              = None
        self.payload_filter_function = None

        if not os.path.exists(project.coverage_dir):
            os.mkdir(project.coverage_dir)

    def loadPayloadFilter(self):
        if self.project.payload_filter == None:
            return True
        if not os.path.exists(self.project.payload_filter):
            log.warn("Payload filter (file: '%s') does not exist!" % self.project.payload_filter)
            return False
        saved_sys_path = sys.path
        try:
            payload_filter_file_without_ext = os.path.splitext(self.project.payload_filter)[0]
            payload_filter_module_path = os.path.dirname(payload_filter_file_without_ext)
            payload_filter_module_name = os.path.basename(payload_filter_file_without_ext)
            sys.path.insert(0, payload_filter_module_path)
            payload_filter_module = __import__(payload_filter_module_name)
            self.payload_filter_function = payload_filter_module.payload_filter_function
            sys.path = saved_sys_path
        except Exception as e:
            sys.path = saved_sys_path
            log.warn("loadPayloadFilter: " + str(e))
            log.debug("Full Stack Trace:\n" + traceback.format_exc())
            return False

        sys.path = saved_sys_path
        return True

    def runPayloadFilterFunction(self, fuzz_pkt):
        """
        Returns a filtered version of the fuzz payload (as bytes object)
        or None if the payload should not be used by the fuzzer.
        The payload is first passed through the user-provided payload
        filter (if specified). The filter may modify the payload before
        returning or decide to not return any payload (None) in which
        case the fuzzer should skip the payload.
        """
        if self.payload_filter_function != None:
            try:
                fuzz_pkt = self.payload_filter_function(fuzz_pkt)
            except Exception as e:
                log.warn("The payload filter '%s' caused an exception: %s" % (self.project.payload_filter, str(e)))
                log.debug("Full Stack Trace:\n" + traceback.format_exc())
            if not isinstance(fuzz_pkt, bytes) and fuzz_pkt != None:
                log.warn("The payload filter '%s' returned unsupported type: '%s'."
                            % (self.project.payload_filter, str(type(fuzz_pkt))))
                return None

        return fuzz_pkt

    def getMutatedPayload(self, pkt_file, seed):
        """
        Returns a mutated version of the content inside pkt_file (as bytes object)
        or None if the payload should not be used by the fuzzer.
        """

        fuzz_pkt = check_output(["radamsa", "-s", str(seed), pkt_file])
        if self.project.max_payload_size > 0 and len(fuzz_pkt) > self.project.max_payload_size:
            fuzz_pkt = fuzz_pkt[:self.project.max_payload_size]

        return fuzz_pkt


    def sendFuzzPayload(self, payload):
        """
        Send fuzzing payload to target process via TCP socket
        """

        dest = (self.project.host, self.project.port)
        try:
            if not self.project.udp:
                # TCP
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(dest)
                if self.project.ssl:
                    s = ssl.wrap_socket(s)

                s.sendall(payload)
                if self.project.recv_timeout:
                    s.settimeout(self.project.recv_timeout)
                    s.recv(1)

            else:
                # UDP (only send single UDP packets)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(payload, dest)

        except IOError as e:
            #log.debug("IOError: " + str(e))
            pass
        except EOFError as e:
            #log.debug("EOFError: " + str(e))
            pass
        s.close()

    def sendFuzzPayloadInProcess(self, payload):
        """
        Send fuzzing payload to target[0] process by invoking the target function
        directly in frida
        """

        # Call function under fuzz:
        encoded = payload.hex()
        coverage_blob = self.targets[0].frida_script.exports.fuzz(encoded)
        #log.info("sendFuzzPayloadInProcess: len=%d" % len(coverage_blob))
        # the fuzz call may cause a frida.core.RPCException, e.g. when the function
        # causes a segfault. we do not catch the exeception here, but in doIteration
        # where it is registered as a crash

    def waitForCoverage(self, timeout):
        """
        Continiously checks the frida script of all targets if their stalker got attached.
        
        Returns a tupel:
          idx 0: the target if the stalker was attached or None if the timeout was hit.
          idx 1: the stalker_attached boolean  (stalker has been attached in the target process)
          idx 2: the stalker_finished boolean  (stalker has completed)

        The target (if found) is also set as the active_target
        """
        # Create an ordered list of targets to check (last active target is checked first)
        targets = []
        if self.active_target != None:
            targets.append(self.active_target)
            targets.extend([t for t in self.targets if t != self.active_target])
        else:
            targets = self.targets

        # Wait for timeout seconds for any of the stalkers to get attached
        # (i.e. we hit the target function)
        start = time.time()
        while (time.time()-start) < timeout:
            for target in self.targets:
                stalker_attached, stalker_finished = target.frida_script.exports.checkstalker()
                if stalker_attached:
                    # Found the right target
                    self.active_target = target
                    return (target, stalker_attached, stalker_finished)
        return (None, False, False)

    def getCoverageOfPayload(self, payload, timeout=0.04, retry=0):
        """
        Sends of the payload and checks the returned coverage.
        If the payload_filter was specified by the user, the payload
        will first be passed through it.
        All targets will then be checked for coverage. The function only
        succeeds if just one target has produced a coverage.

        Important:
            Frida appears to have a bug sometimes in collecting traces with the
            stalker.. no idea how to fix this yet.. hence we do a retry. This
            can however screw up the replay functionality and should be fixed
            in the future.

        Arguments:
            payload {bytes} -- payload which shall be sent to the target

        Keyword Arguments:
            timeout {float} -- [description] (default: {0.1})
            retry {int} -- [description] (default: {5})

        Returns:
            {set} -- set of basic blocks covered by the payload
        """

        payload = self.runPayloadFilterFunction(payload)
        if payload == None:
            return set()

        cov = None
        cnt = 0
        while cnt <= retry:
            # Clear coverage info in all targets:
            for target in self.targets:
                target.frida_script.exports.clearcoverage()

            # Send payload
            if self.project.fuzz_in_process:
                self.sendFuzzPayloadInProcess(payload)
            else:
                self.sendFuzzPayload(payload)

            # Wait for timeout seconds for any of the stalkers to get attached
            target, stalker_attached, stalker_finished = self.waitForCoverage(timeout)

            if target != None:
                # Found a target that has attached their stalker. Wait for the stalker
                # to finish and then extract the coverage.
                # Wait for 1 second <- maybe this should be adjusted / configurable ?
                start = time.time()
                while not stalker_finished and (time.time()-start) < 1:
                    stalker_attached, stalker_finished = target.frida_script.exports.checkstalker()

                if not stalker_finished:
                    log.info("getCoverageOfPayload: Stalker did not finish after 1 second!")
                    break

                cov = target.frida_script.exports.getcoverage()
                if cov != None and len(cov) > 0:
                    break

            else:
                # None of the targets' function was hit. next try..
                cnt += 1

        if cov == None or len(cov) == 0:
            log.debug("getCoverageOfPayload: got nothing!")
            return set()

        return parse_coverage(cov, self.active_target.watched_modules)


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
                coverage = self.getCoverageOfPayload(fuzz_pkt, timeout=1)
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

            write_drcov_file(self.active_target.modules, coverage_last,
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
            fuzz_pkt = self.getMutatedPayload(pkt_file, seed)
            if fuzz_pkt == None:
                continue

            # Writing History file for replaying
            open(self.project.project_dir + "/frida_fuzzer.history", "a").write(str(pkt_file) + "|" + str(seed) + "\n")

            try:
                coverage = self.getCoverageOfPayload(fuzz_pkt)
            except (frida.TransportError, frida.InvalidOperationError, frida.core.RPCException) as e:
                log.warn("doIteration: Got a frida error: " + str(e))
                log.debug("Full Stack Trace:\n" + traceback.format_exc())
                log.info("Current iteration: " + time.strftime("%Y-%m-%d %H:%M:%S") +
                         " [seed=%d] [file=%s]" % (seed, pkt_file))
                crash_file = self.project.crash_dir + time.strftime("/%Y%m%d_%H%M%S_crash")
                with open(crash_file + "_" + str(self.active_target.process_pid), "wb") as f:
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

                cov_file = self.project.coverage_dir + "/" + str(seed) + "_" + pkt_file.split("/")[-1]
                write_drcov_file(self.active_target.modules, coverage, cov_file)
                write_drcov_file(self.active_target.modules, coverage.difference(self.accumulated_coverage),
                                         cov_file + "_diff")

                self.project.last_new_path = seed
                self.accumulated_coverage = self.accumulated_coverage.union(coverage)
                write_drcov_file(self.active_target.modules, self.accumulated_coverage,
                                 self.project.coverage_dir + "/accumulated_coverage.drcov")

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
                    fuzz_pkt = self.getMutatedPayload(pkt_file, int(seed.strip()))
                    if fuzz_pkt == None:
                        continue
                    if self.project.debug_mode:
                        open(self.project.debug_dir + "/history", "a").write("file: {} seed: {} \n{}\n".format(
                            pkt_file,
                            seed,
                            fuzz_pkt,
                            ))
                    coverage = self.getCoverageOfPayload(fuzz_pkt)
                    log.info("Current iteration: " + time.strftime("%Y-%m-%d %H:%M:%S") +
                                " [seed=%d] [file=%s]" % (int(seed.strip()), pkt_file))
                except (frida.TransportError, frida.InvalidOperationError, frida.core.RPCException) as e:
                    log.finish_update("doReplay: Got a frida error: " + str(e))
                    log.debug("Full Stack Trace:\n" + traceback.format_exc())
                    log.finish_update("Current iteration: " + time.strftime("%Y-%m-%d %H:%M:%S") +
                                " [seed=%d] [file=%s]" % (int(seed.strip()), pkt_file))
                    log.finish_update("Server Crashed! Lets narrow it down")
                    #crash_file = self.crash_dir + time.strftime("/%Y%m%d_%H%M%S_crash")
                    #with open(crash_file, "wb") as f:
                    #    f.write(fuzz_pkt)
                    #log.info("Payload is written to " + crash_file)
                    return False

                if coverage == None:
                    log.warn("No coverage was generated for [%d] %s!" % (seed, pkt_file))

        log.warn("Replay did not crash the Server!")
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
            log.warn("Corpus is empty, please use the 'add' subcommand to add files to it.")
            return False

        # Collect coverage
        dict_of_infile_coverages = {}
        loop_counter = 0
        for infile in corpus:
            loop_counter += 1
            fuzz_pkt = open(infile, "rb").read()
            failed_coverage_count = 0
            tmp_accu_cov = set()
            RETRIES = 5
            for i in range(RETRIES):
                t = time.strftime("%Y-%m-%d %H:%M:%S")
                log.update(t + " Collecting coverage for corpus files (%d/%d) ... [iteration=%d] %s"
                            % (loop_counter, len(corpus), i, infile))

                # send packet to target
                coverage = self.getCoverageOfPayload(fuzz_pkt, timeout=0.2)
                if coverage == None or len(coverage) == 0:
                    failed_coverage_count += 1
                    continue

                # Accumulate coverage:
                tmp_accu_cov = tmp_accu_cov.union(coverage)

            if failed_coverage_count == RETRIES:
                log.warn("Coverage for %s was always 0 (%d retries)" % (infile, RETRIES))
                # note: file will be removed later..

            dict_of_infile_coverages[infile] = tmp_accu_cov
            self.accumulated_coverage = self.accumulated_coverage.union(tmp_accu_cov)
            write_drcov_file(self.active_target.modules, tmp_accu_cov,
                                 self.project.coverage_dir + "/" + infile.split("/")[-1])

        log.finish_update("Collected coverage for corpus (%d basic blocks from %d files in corpus)"
                            % (len(self.accumulated_coverage), len(corpus)))

        # Filter all corpus files with a coverage that is a direct subset of another corpus file
        loop_counter = 0
        for infile in corpus:
            loop_counter += 1
            log.update("(%d/%d) Comparing %s (%d bblocks) against rest of the corpus..." 
                        % (loop_counter, len(corpus), infile, len(dict_of_infile_coverages[infile])))
            for other_infile in [f for f in corpus if f != infile]:
                if dict_of_infile_coverages[infile].issubset(dict_of_infile_coverages[other_infile]):
                    log.info("%s coverage is direct subset of %s. Moving to trash..." % (infile, other_infile))
                    backup_file = self.project.corpus_trash_dir + "/" + infile.split("/")[-1]
                    shutil.move(infile, backup_file)
                    break

        corpus_new = [self.project.corpus_dir + "/" + x for x in os.listdir(self.project.corpus_dir)]
        acc_cov_new = set.union(*dict_of_infile_coverages.values())
        log.finish_update("Remaining input files: %d (total of %d basic blocks)." % (
                         len(corpus_new), len(acc_cov_new)))
        self.corpus = corpus_new
        return True

    def fuzzerLoop(self):
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
        """
        Attach frida to all specified targets (project.targets)
        """
        scriptfile = os.path.join(os.path.dirname(__file__),'frida_script.js')
        log.info("Loading script: %s" % scriptfile)
        script_code = open(scriptfile, "r").read()

        for target in self.targets:
            if not target.attach(script_code):
                return False
            if target.getModuleMap() == None:            # Query the loaded modules from the target
                return False
            if not target.createModuleFilterList():      # ... and create the module filter list
                return False
        return True

    def detach(self):
        """
        Detach frida from all targets.
        """
        for target in self.targets:
            target.detach()


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

    if args.command == None:
        parser.print_help()
        sys.exit(-1)
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
        if not project.loadProject(args.project, args):
            log.warn("Error: Could not load project '%s'!" % args.project)
            return

        if project.getInstance().logfile_name != None:
            log.logfile = open(project.getInstance().logfile_name, "wb", 0)

        if not project.getInstance().colored_output:
            log.use_color = False
            log.CLEAR_LINE = ""      # no escape sequences for the no-color option!

    if args.command in ["fuzz", "replay", "minimize"]:
        # Create Fuzzer and attach to target
        fuzzer = FridaFuzzer(project.getInstance())
        if not fuzzer.attach():
            return
        if not fuzzer.loadPayloadFilter():
            return

        # Invoke subcommand function with instantiated fuzzer
        args.func(args, fuzzer)

        log.info("Detach Fuzzer ...")
        fuzzer.detach()

    else:
        # Invoke subcommand function
        args.func(args)

    log.info("Done")
    if log.logfile != None:
        log.logfile.close()
    return


if __name__ == "__main__":
    main()
