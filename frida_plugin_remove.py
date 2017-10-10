from frida_plugin import FridaPlugin

from binaryninja import *

class FridaPluginRemove(FridaPlugin):
    def __init__(self, settings):
        super(FridaPluginRemove, self).__init__(settings)
    
    def is_valid(self, bv, function=None):
        addr = "0x%x" % function.start
        if self.intercepts:
            if addr in self.intercepts:
                if self.intercepts[addr].is_enabled:
                    return True
        return False
    
    def run(self, bv, function=None):
        addr = "0x%x" % function.start
        function.set_auto_instr_highlight(function.start, HighlightStandardColor.NoHighlightColor)
        log.log_info("Frida Plugin: Stopping intercept at %s" % addr)
        self.intercepts[addr].disable()