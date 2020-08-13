# FRIZZER - target.py
#
# 
#
# Author: Dennis Mantz (ERNW GmbH)
#         Birk Kauer   (ERNW GmbH)

import frida

# frizzer modules
from frizzer import log

class Target():
    """
    This class represents a fuzz-target to which frizzer will attach
    with frida.
    """

    def __init__(self, name, target_dict):

        self.name             = name
        self.frida_session    = None
        self.frida_script     = None
        self.process_name     = None
        self.process_pid      = None
        self.remote_frida     = False
        self.frida_port       = 27042
        self.modules          = None        # Modules which are loaded in the process
        self.modules_to_watch = None        # Modules which where given in the config file
                                            # for which the coverage should be tracked
        self.watched_modules = None         # intersection of self.modules and self.modules_to_watch

        if "function" in target_dict:
            self.function = target_dict["function"]
        else:
            log.warn("No 'function' in target-section '%s'!" % name)
            return False

        if "process_name" in target_dict:
            self.process_name = target_dict["process_name"]
        if "process_pid" in target_dict:
            self.process_pid = target_dict["process_pid"]
        if "remote_frida" in target_dict:
            self.remote_frida = target_dict["remote_frida"]
        if "frida_port" in target_dict:
            self.frida_port = target_dict["frida_port"]
        if "modules" in target_dict:
            self.modules_to_watch = target_dict["modules"]

        if self.remote_frida:
            self.frida_instance = frida.get_device_manager().add_remote_device('%s:%d' % ('localhost', self.frida_port))
        else:
            self.frida_instance = frida



    def loadScript(self, script_code):
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
        self.frida_script = script
        return True

    def attach(self, script_code):
        """
        Attach frida to the target
        """

        if self.process_pid != None:
            target_process = int(self.process_pid)
        elif self.process_name != None:
            target_process = self.process_name
        else:
            log.warn("'%s'.attach: No process specified with 'process_name' or 'pid'!" % self.name)
            return False

        try:
            if self.remote_frida:
                self.frida_session = self.frida_instance.attach(target_process)
            else:
                self.frida_session = self.frida_instance.attach(target_process)
        except frida.ProcessNotFoundError as e:
            log.warn("'%s'.attach: %s" % (self.name, str(e)))
            return False

        self.loadScript(script_code)

        pid = self.frida_script.exports.getpid()
        log.info("'%s'.attach: Attached to pid %d!" % (self.name, pid))
        self.process_pid = pid

        function_address = self.function
        if isinstance(function_address, str):
            function_address = int(self.frida_script.exports.resolvesymbol(self.function), 0)
            if function_address > 0:
                log.info("Target function '%s' is at address %s!" % (self.function, function_address))
            else:
                log.warn("No symbol with name '%s' was found!" % self.function)
                self.detach()
                return False

        self.frida_script.exports.settarget(function_address)
        return True

    def detach(self):
        try:
            self.frida_script.unload()
        except frida.InvalidOperationError as e:
            log.warn("'%s'.detach: Could not unload frida script: %s" % (self.name,str(e)))

        self.frida_session.detach()


    def getModuleMap(self):
        if self.frida_script == None:
            log.warn("'%s'.getModuleMap: self.frida_script is None!" % self.name)
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
            log.warn("'%s'.createModuleFilterList: self.modules is None!" % self.name)
            return False

        self.watched_modules = []
        for module in self.modules:
            for search_term in self.modules_to_watch:
                if search_term in module["path"]:
                    self.watched_modules.append(module)

        if len(self.watched_modules) == 0:
            paths = "\n".join([m["path"] for m in self.modules])
            log.warn("'%s'.createModuleFilterList: No module was selected! Possible choices:\n%s" % (self.name, paths))
            return False
        else:
            paths = "\n".join([m["path"] for m in self.watched_modules])
            log.info("'%s'.createModuleFilterList: Filter coverage to only include the following modules:\n%s" % (self.name, paths))
            return True
