from frida_plugin import FridaPlugin

from binaryninja import *

class FridaPluginSelectModule(FridaPlugin):
    def __init__(self, settings):
        super(FridaPluginSelectModule, self).__init__(settings)
    
    def is_valid(self, bv, function=None):
        return self.frida_session != None
    
    def run(self, bv, function=None):
        frida_modules = self.frida_session.enumerate_modules()
        modules = []
        for module in frida_modules:
            modules.append(module.name)
        choice_f = ChoiceField("Modules", modules)
        get_form_input([choice_f], "Select Process Module")
        if choice_f.result != None:
            self.module_name = modules[choice_f.result]
            for addr, intercept in self.intercepts.items():
                intercept.set_module_name(self.module_name)