# FRIZZER - project.py
#
# 
#
# Author: Dennis Mantz (ERNW GmbH)
#         Birk Kauer   (ERNW GmbH)

import os
import time
import toml
import frida

# frizzer modules
from frizzer import log
from frizzer.target import Target

CONFIG_TEMPLATE = """
[fuzzer]
log_level       = 3              # 3=debug   2=info   1=warning
write_logfile   = true           # writes a .log file to the project directory
debug_mode      = false          # write additional debug logs
host            = "localhost"    # host on which the target process listens
port            = 7777           # port on which the target process listens
ssl             = false          # (only for TCP) wraps the TCP socket in a SSL context
udp             = false          # Use UDP instead of TCP
fuzz_in_process = false          # use in-process fuzzing instead of fuzzing over the network
recv_timeout    = 0.1
colored_output  = true           # use ANSI Escape Codes to color terminal output
max_payload_size= 0              # Maximum size for fuzz payloads in bytes. 0 = no limit.
#payload_filter  = "path/to/filter.py"   # Define a filter for the mutated payloads (written in Python 3)
                                         # The python file must contain the following function:
                                         # def payload_filter_function(payload):
                                         #     # do stuff. (payload is 'bytes' object)
                                         #     return modified_payload_or_None

[target]
process_name    = "myprocess"    # Process name of the target. Must be unique, otherwise use process_pid
#process_pid     = 1234          # Specifify the target process via process ID
function        = 0x123456       # Function for which the coverage will be traced
                                 # Can either be an absolute address (integer, e.g. 0x12345)
                                 # or a symbol name (string, e.g. "handleClient")
remote_frida    = false          # Connect to a "remote" frida server (needs ssh portforwarding of the
                                 # frida server port to localhost)
frida_port      = 27042          # port for the remote frida connection. frizzer will connect to localhost:$PORT

# 'modules' is a filter list. Coverage will be traced only for modules / shared
# libs which match one of the search terms in 'modules'. It is important that
# the filter matches at least one module!
modules = [ 
        "tests/simple_binary/test",
    ]

# Multiple targets are supported but you probably don't want this
# (only meant for load-balancing setups were multiple processes handle the network traffic)
#[target2]
#process_name    = "myprocess"
#function        = 0x123456
#remote_frida    = true
#frida_port      = 27042
#modules = [
#        "tests/simple_binary/test",
#    ]
"""

# Singleton instance (can be accessed from everywhere)
instance = None

def getInstance():
    global instance
    if instance == None:
        log.warn("Project instance was not yet created!")
    return instance

def loadProject(project_dir, args=None):
    """
    Loads the project given by 'project_dir' (directory name) as global singleton instance
    which can be retrieved by getInstance() afterwards.
    If args is not None, it will be used to temporarily overwrite certain project settings
    like pid, seed, etc.
    """
    global instance
    if instance != None:
        log.warn("Project instance does already exist!")
        return False

    proj = Project(project_dir)
    if not proj.loadProject(args):
        log.warn("Could not load project")
        return False

    instance = proj
    return True

def createProject(project_dir):
    os.mkdir(project_dir)
    proj = Project(project_dir)
    if not proj.checkAndCreateSubfolders():
        return False
    with open(proj.config_file, "w") as f:
        f.write(CONFIG_TEMPLATE)
    return True


class Project():
    """
    This class holds all project settings and states. It provides functions to 
    parse the project config file and read/write the state file.
    """

    def __init__(self, project_dir):
        self.project_dir       = project_dir

        # Settings from the config file
        self.targets          = []
        self.port             = None
        self.host             = None
        self.ssl              = False
        self.udp              = False
        self.recv_timeout     = None
        self.fuzz_in_process  = False
        self.corpus           = None
        self.corpus_dir       = project_dir + "/corpus"
        self.corpus_trash_dir = project_dir + "/corpus_trash"
        self.crash_dir        = project_dir + "/crashes"
        self.coverage_dir     = project_dir + time.strftime("/%Y%m%d_%H%M%S_coverage")
        self.debug_dir        = project_dir + "/debug"
        self.config_file      = project_dir + "/config"
        self.state_file       = project_dir + "/state"
        self.debug_mode       = False
        self.logfile_name     = None
        self.colored_output   = True
        self.max_payload_size = 0
        self.payload_filter   = None


        # State
        self.pid               = None
        self.seed              = 0
        self.crashes           = 0
        self.last_new_path     = -1


    def loadProject(self, args):

        # Load config file
        if not os.path.exists(self.config_file):
            log.warn("Config file %s does not exist!" % self.config_file)
            return False
        proj = toml.loads(open(self.config_file).read())

        log.info("Project: " + repr(proj))

        if not "fuzzer" in proj:
            log.warn("Section 'fuzzer' was not found in config file.")
            return False
        fuzzer = proj["fuzzer"]
        if "fuzzer" in proj:
            if "log_level" in fuzzer:
                log.log_level   = fuzzer["log_level"]
            if "write_logfile" in fuzzer:
                if fuzzer["write_logfile"]:
                    self.logfile_name = self.project_dir + time.strftime("/%Y%m%d_%H%M%S_stdout.log")
            if "colored_output" in fuzzer:
                self.colored_output = fuzzer["colored_output"]
            if "debug_mode" in fuzzer:
                self.debug_mode = fuzzer["debug_mode"]
            if "host" in fuzzer:
                self.host = fuzzer["host"]
            if "port" in fuzzer:
                self.port = fuzzer["port"]
            if "ssl" in fuzzer:
                self.ssl = fuzzer["ssl"]
            if "udp" in fuzzer:
                self.udp = fuzzer["udp"]
                if self.udp and 'ssl' in fuzzer and self.ssl:
                    log.warn("SSL can not be used with UDP sockets. SSL will be ignored.")
            if "recv_timeout" in fuzzer:
                self.recv_timeout = fuzzer["recv_timeout"]
            if "fuzz_in_process" in fuzzer:
                self.fuzz_in_process = fuzzer["fuzz_in_process"]
            if "max_payload_size" in fuzzer:
                self.max_payload_size = fuzzer["max_payload_size"]
            if "payload_filter" in fuzzer:
                self.payload_filter = fuzzer["payload_filter"]

        targets = [t for t in proj.keys() if t.startswith('target')]
        if len(targets) == 0:
            log.warn("No 'target' sections were not found in config file (section starting with 'target...').")
            return False

        for target in targets:
            targetobj = Target(target, proj[target])
            self.targets.append(targetobj)

        # Load state file
        if os.path.exists(self.state_file):
            state = toml.loads(open(self.state_file).read())
            if "seed" in state:
                self.seed = state["seed"]
            if "crashes" in state:
                self.crashes = state["crashes"]
            if "last_new_path" in state:
                self.last_new_path = state["last_new_path"]
            log.info("Found old state. Continuing at seed=%d" % (self.seed))

        # Load command line parameters
        if args != None:
            if 'pid' in args and args.pid != None:
                self.pid = args.pid
            if 'seed' in args and args.seed != None:
                self.seed = args.seed
            if 'function' in args and args.function != None:
                self.target_function = args.function
            if 'debug' in args and args.debug == True:
                self.debug_mode = True

        return True

    def saveState(self):
        state = {"seed":            self.seed,
                 "crashes":         self.crashes,
                 "last_new_path":   self.last_new_path}
        open(self.state_file, "w").write(toml.dumps(state))
        return True

    def checkAndCreateSubfolders(self):
        """
        Check whether alls necessary subdirectories exist in the
        project folder. Create them if necessary.
        """
        if not os.path.exists(self.project_dir):
            log.warn("Project directory '%s' does not exist." % self.project_dir)
            return False

        if not os.path.exists(self.debug_dir):
            os.mkdir(self.debug_dir)

        if os.path.exists(self.debug_dir + "/history"):
            log.debug("Deleting old Debug file: " + self.debug_dir + "/history")
            os.remove(self.debug_dir + "/history")

        #if not os.path.exists(self.coverage_dir):
        #    os.mkdir(self.coverage_dir)

        if not os.path.exists(self.crash_dir):
            os.mkdir(self.crash_dir)

        if not os.path.exists(self.corpus_dir):
            os.mkdir(self.corpus_dir)

        if not os.path.exists(self.corpus_trash_dir):
            os.mkdir(self.corpus_trash_dir)

        return True

