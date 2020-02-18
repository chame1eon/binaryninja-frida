from binaryninja import *

import frida
import os
import json

from .frida_intercept import FridaIntercept

class FridaPlugin(object):
    def __init__(self, settings):
        self.settings = settings
        self.frida_device = None
        self.frida_session = None
        self.module_name = None
        self.intercepts = None
        self.global_bv = None
        
    def _load_metadata(self, bv):
        try:
            self.intercepts = {}
            serialized_intercepts = json.loads(bv.query_metadata("frida_plugin_intercepts"))
            
            for addr, intercept in list(serialized_intercepts.items()):
                if addr not in self.intercepts:
                    self.intercepts[addr] = FridaIntercept.deserialize(intercept)
                    
                    if self.intercepts[addr].is_enabled:
                        function = bv.get_functions_containing(int(addr, 16))[0]
                        function.set_auto_instr_highlight(int(addr, 16), HighlightColor(red=0xEF, blue=0x64, green=0x56))
        except KeyError:
            pass

    def _store_metadata(self, bv):
        serialized_intercepts = {}
        for addr, intercept in list(self.intercepts.items()):
            serialized_intercepts[addr] = intercept.serialize()

        bv.store_metadata("frida_plugin_intercepts", json.dumps(serialized_intercepts))
        
    def _check_and_load_metadata(self, bv):
        if "intercepts" not in bv.session_data:
            self._load_metadata(bv)
            
    def _load_session_data(self, bv):
        if "intercepts" in bv.session_data:
            self.intercepts = bv.session_data["intercepts"]
        if "frida_device" in bv.session_data:
            self.frida_device = bv.session_data["frida_device"]
        if "frida_session" in bv.session_data:
            self.frida_session = bv.session_data["frida_session"]
        if "module_name" in bv.session_data:
            self.module_name = bv.session_data["module_name"]
    
    def _store_session_data(self, bv):
        bv.session_data["intercepts"] = self.intercepts
        bv.session_data["frida_device"] = self.frida_device
        bv.session_data["frida_session"] = self.frida_session
        bv.session_data["module_name"] = self.module_name
    
    def _reload_intercepts(self):
        for addr, intercept in list(self.intercepts.items()):
            intercept.update_function_def(self.global_bv.get_functions_containing(int(addr, 16))[0])
            if intercept.is_running and intercept.is_invalidated():
                intercept.reload(self.frida_session.create_script(intercept.to_frida_script()))
    
    def _build_or_get_intercept(self, bv, addr, function):
        if addr not in self.intercepts:
            self.intercepts[addr] = FridaIntercept.from_bn_function(function, bv.start, self.module_name)
            return self.intercepts[addr]
        else:
            return self.intercepts[addr]
            
    def _run(self, bv, function=None):
        self._load_session_data(bv)
        self._check_and_load_metadata(bv)
        self.global_bv = bv
        self.run(bv, function)
        self._reload_intercepts()
        self._store_metadata(bv)
        self._store_session_data(bv)
    
    def run(self, bv, function=None):
        raise RuntimeException("Error: Frida Plugin Module must implement a run method.")
    
    def _is_valid(self, bv, function=None):
        self._load_session_data(bv)
        return self.is_valid(bv, function)
    
    def is_valid(self, bv, function=None):
        return True