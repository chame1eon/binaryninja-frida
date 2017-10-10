from frida_plugin import FridaPlugin

class FridaPluginStop(FridaPlugin):
    def __init__(self, settings):
        super(FridaPluginStop, self).__init__(settings)
    
    def run(self, bv, function=None):
        for addr, intercept in self.intercepts.items():
            if intercept.is_enabled == True:
                log.log_info("Frida Plugin: Removing intercept at %s" % intercept.addr)
                intercept.stop()
                intercept.is_enabled = False
        
        if self.frida_session:
            self.frida_session.detach()
        self.frida_session = None