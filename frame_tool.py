import volatility.obj as obj
import volatility.plugins.linux.common as common
import json
import socket
import volatility.plugins.linux.netstat as linux_netstat
import tempfile
import sys
import os
import volatility.utils as utils
import volatility.conf as conf
import volatility.plugins.linux.plthook as plthook
up_one = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, up_one)
from resources.strategy_classes import *

# Usage python volatility/vol.py --[absolute path to]/plc_mal_tools/ -f [dump file] --profile=[profile of target os] frametool --configuration [absolute path to configuration file].json

class FrameTool(common.AbstractLinuxIntelCommand):
    plc_type = {}
    def __init__(self, config, *args, **kwargs):
        common.AbstractLinuxIntelCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('CONFIGURATION', short_option = "c", default = None, help = "Provide configuration file directory", action = 'store')


    def get_config(self, configuration_file):
        configuration_dict = {"firmware": None,
                 "protocol": None,
                 "targets": []}
        config = open(configuration_file)

        content = json.load(config)

        try:
            configuration_dict["firmware"] = content["firmware"]
            print "Acquired firmware config."
        except:
            print "Unable to load firmware type, check config file."
        try:
            configuration_dict["protocol"] = content["protocol"]
            print "Acquired protocol config."
        except:
            print "Unable to load protocol type, check config file."
        try:
            configuration_dict["targets"] = content["targets"]
            print "Acquired targets config."
        except:
            print "Unable to load targets, check config file. Target values\
            should be strings in an array."

        return configuration_dict

    def configure(self):
        self.jsn_file = str(self._config.CONFIGURATION)
        print "Building...\n"
        self.plc_type = self.get_config(self.jsn_file)
        self.strategy = decider(self)
        return


    def calculate(self):
        #Prepare configuration for passing to method based on firmware/protocol
        common.set_plugin_members(self)
        plugin_conf = self.configure()
        #pass self to arbitrary method, return conns object, which can be further analyzed
        conns = self.strategy.get_IO_conns()
        connected_pids = []
        hooks = []
        #
        for line in conns:
            connected_pids.append(line[0])
            print(str(line[0]))
        for pid in connected_pids:
            curr_hook = self.strategy.hooked_funcs(str(pid))
            hooks.append(curr_hook)
        outs = (conns, hooks)
        return outs

    def render_text(self, outfd, data):
        outfd.write("Completing analysis\n")
        outfd.write("The following processes are connected to targeted devices: \n")
        outfd.write("-" * 40 +"\n")
        for line in data[0]:
            outfd.write(line[1])
        outfd.write("-" * 40 +"\n")
        outfd.write("The following hooks were found in the connected process' protocol library: \n")
        show_hooks = self.strategy.filter_for_elfs(outfd, data[1])
        show_hooks()
