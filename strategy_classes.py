import volatility.obj as obj
import volatility.plugins.linux.common as common
import volatility.plugins.linux.netstat as linux_netstat
import volatility.plugins.linux.plthook as plthook
import volatility.utils as utils
import volatility.conf as conf
import socket

class Strategy(common.AbstractLinuxIntelCommand):
    def __init__(self, previous_object):
        if previous_object:
            self._config = previous_object._config
            self.plc_type = previous_object.plc_type

    def get_IO_conns(targets):
        print "Please choose firmware type."

class Open_plc(Strategy):
    def __init__(self, *args):
        super(Open_plc, self).__init__(*args)

    def get_IO_conns(targets):
        print "Please choose IO communication protocol."

class Open_plc_modbusTCP(Open_plc):
    def __init__(self, *args):
        super(Open_plc_modbusTCP, self).__init__(*args)

    def get_IO_conns(plugin_obj):
        #setup for passing obj to outside plugin
        plugin_conf = conf.ConfObject()
        plugin_conf.PROFILE = plugin_obj._config.PROFILE
        common.set_plugin_members(plugin_obj)
        net_plugin = linux_netstat.linux_netstat(plugin_conf)
        data = net_plugin.calculate()
        filtered_conns = Open_plc_modbusTCP.filter_for_targets(plugin_obj, data)

        return filtered_conns

    def hooked_funcs(plugin_obj, proc_id):
        plugin_conf = conf.ConfObject()
        plugin_conf.PROFILE = plugin_obj._config.PROFILE
        plugin_conf.PID = proc_id
        common.set_plugin_members(plugin_obj)
        hook_plugin = plthook.linux_plthook(plugin_conf)
        hooks = hook_plugin.calculate()
        return hooks

    def filter_for_elfs(self, outfd, data):
        #based on plthook renderer
        common.set_plugin_members(self)
        for proc_id in data:
            outfd.write("" * 40 + "\n")
            self.table_header(outfd, [("Task", "10"),
                                      ("ELF Start", "[addrpad]"),
                                      ("ELF Name", "24"),
                                      ("Symbol", "24"),
                                      ("Resolved Address", "[addrpad]"),
                                      ("H", "1"),
                                      ("Target Info", "")])

            ignore = frozenset(self._config.IGNORE)
            #In addition to displaying output of plthook scan, filters for specific modbus library
            for task in proc_id:
                for soname, elf, elf_start, elf_end, addr, symbol_name, hookdesc, hooked in task.plt_hook_info():
                    if not hooked and not self._config.ALL:
                        continue

                    if hookdesc in ignore:
                        continue

                    if hookdesc == '[RTLD_LAZY]' and not self._config.ALL:
                        continue

                    if soname != 'libmodbus.so.5':
                        continue
                    self.table_row(outfd, task.pid, elf_start, soname if soname else '[main]', \
                        symbol_name, addr, '!' if hooked else ' ', hookdesc)

    def filter_for_targets(plugin_obj, data):
        #Iterate through netstat data, looking for target IPs; based on linux_netstat renderer
        conns_to_sens_acts = []
        sens_acts = plugin_obj.plc_type["targets"]
        for targ in sens_acts:
            for conn in data:
                for ents in conn.netstat():
                    if ents[0] == socket.AF_INET:
                        (_, proto, saddr, sport, daddr, dport, state) = ents[1]
                        fields = "{0:8s} {1:<16}:{2:>5} {3:<16}:{4:>5} {5:<15s} {6:>17s}/{7:<5d}\n"
                        connection = fields.format(proto, saddr, sport, daddr, dport, state, conn.comm, conn.pid)
                        #print(connection)
                        source = str(saddr)
                        destination = str(daddr)
                        if (source == targ) or (destination == targ):
                            #print(connection)
                            conns_to_sens_acts.append((conn.pid, connection))

        return conns_to_sens_acts

#Function to mutate Frame object into specific solution
def decider(frame_object):
    """
    map {} is the dictionary of builder functions. As the list of possible configuration
    classes grows, this dictionary should be updated so the appropriate class can be chosen.
    JSON configuration file entries should also be based on the keys of this dictionary.
    The keys should be a simple concatenation of the firmware and the protocol, e.g. to
    select the class Open_plc_modbusTCP, the firmware entry in the configuration file should
    be 'OpenPLC', and the protocol entry should be 'ModbusTCP'.
    """
    #Recast functions
        #recast function for OpenPLC on Modbust TCP
    def OpenPLCModbusTCP(abstract_strat):
        strat = Open_plc_modbusTCP(abstract_strat)
        return strat

    config_dictionary = frame_object.plc_type
    selector = config_dictionary["firmware"] + config_dictionary["protocol"]

    map = {"OpenPLCModbusTCP": OpenPLCModbusTCP}
    chosen_method = map.get(selector, lambda: "Invalid type.")
    specific_strategy = chosen_method(frame_object)
    print("Configuration processed... Your device is a: " + str(selector))
    return specific_strategy
