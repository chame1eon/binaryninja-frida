from frida_plugin import FridaPlugin

from binaryninja import *

class FridaPluginIntercept(FridaPlugin):
    def __init__(self, settings):
        super(FridaPluginIntercept, self).__init__(settings)
    
    def is_valid(self, bv, function=None):
        addr = "0x%x" % function.start
        if self.intercepts != None:
            if addr not in self.intercepts or not self.intercepts[addr].is_enabled:
                return True
        return False
    
    def run(self, bv, function=None):
        addr = "0x%x" % function.start
        fi = self._build_or_get_intercept(bv, addr, function)
        fi.set_module_name(self.module_name)
    
        log.log_info("Frida Plugin: Intercepting " + function.name + " at %s" % addr)

        fi.enable()
        if self.frida_session:
            fi.start(self.frida_session.create_script(fi.to_frida_script()))
        function.set_auto_instr_highlight(function.start, HighlightColor(red=0xEF, blue=0x64, green=0x56))