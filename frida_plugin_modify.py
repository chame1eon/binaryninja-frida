from frida_plugin import FridaPlugin

from binaryninja import *

class FridaPluginModify(FridaPlugin):
    def __init__(self, settings):
        super(FridaPluginModify, self).__init__(settings)
    
    def run(self, bv, function=None):
        addr = "0x%x" % function.start
        fi = self._build_or_get_intercept(bv, addr, function)
        
        on_enter_label_f = LabelField("Existing On Enter")
        on_enter_f = MultilineTextField("On Enter")
        on_leave_label_f = LabelField("Existing On Leave")
        on_leave_f = MultilineTextField("On Leave")
        get_form_input([on_enter_label_f, fi.onEnter.strip(), on_enter_f, on_leave_label_f, fi.onLeave.strip(), on_leave_f], "Frida Intercept Code")
        if on_enter_f.result != None and on_enter_f.result != None:
            if on_enter_f.result == "" and on_leave_f.result == "":
                fi.reset_on_enter()
                fi.reset_on_leave()
            else:
                fi.set_on_enter(on_enter_f.result)
                fi.set_on_leave(on_leave_f.result)