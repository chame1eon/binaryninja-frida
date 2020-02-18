from .frida_plugin import FridaPlugin

class FridaPluginReload(FridaPlugin):
    def __init__(self, settings):
        super(FridaPluginReload, self).__init__(settings)
        
    def run(self, bv, function=None):
        self._reload_intercepts()