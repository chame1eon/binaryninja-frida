from binaryninja import *

import base64

class FridaIntercept:
    def __init__(self, addr, params, ret, module_name=None, abi='default'):
        self.addr = addr
        self.params = params
        self.ret = ret
        self.module_name = module_name
        self.abi = FridaIntercept.to_frida_abi(abi);
        self.script = None
        self.is_running = False
        self.is_enabled = False
        self.invalidated = False
        
        self.reset_on_enter()
        self.reset_on_leave()
        
    def _on_message(self, message, data):
        log.log_info("Frida Plugin: message received from function at address " + self.addr + ":")
        if message["type"] == "send":
            log.log_info(message["payload"])
            if data:
                log.log_info(data)
        elif message["type"] == "error":
            log.log_error(message["description"])
        
    def set_on_enter(self, onEnter):
        self.onEnter = onEnter
        self.invalidated = True
        
    def reset_on_enter(self):
        on_enter = ''
        for i in range(0, len(self.params)):
            on_enter += 'console.log("args[%d]:", args[%d]);\n' % (i, i)
        self.onEnter = on_enter
        self.invalidated = True
        
    def set_on_leave(self, onLeave):
        self.onLeave = onLeave
        self.invalidated = True
        
    def reset_on_leave(self):
        if self.ret != "void":
            self.onLeave = 'console.log("retval:", retval);'
        else:
            self.onLeave = ''
        self.invalidated = True
        
    def set_module_name(self, module_name):
        self.module_name = module_name
        self.invalidated = True
        
    def update_function_def(self, function):
        params = []
        for p in function.parameter_vars:
            params.append(FridaIntercept.to_frida_type(p.type))
        if params != self.params:
            self.params = params
            self.invalidated = True
        updated_ret = FridaIntercept.to_frida_type(function.return_type)
        if updated_ret != self.ret:
            self.ret = updated_ret
            self.invalidated = True
        
    def to_frida_script(self):
        script = ""
        if self.module_name:
            script += 'var base = Module.findBaseAddress("' + self.module_name + '");\n'
        else:
            script += 'var base = ptr("0x0");\n'
        script += 'var f = new NativeFunction(base.add(ptr("' + self.addr + '")), "' + self.ret + '", ['
        for p in self.params:
            script += '"' + p + '", '
            
        if len(self.params) > 0:
            script = script[:-2]
            
        
        script += ']' + ', "' + self.abi + '"' + ');\n'
        
        script += 'Interceptor.attach(f, {\n'
        
        if self.onEnter:
            script += 'onEnter: function(args) {\n'
            script += self.onEnter + '\n'
            script += '}'
            
        if self.onEnter and self.onLeave:
            script += ',\n'
            
        if self.onLeave:
            script += 'onLeave: function(retval) {\n'
            script += self.onLeave + '\n'
            script += '}\n'
            
        script += '});\n'
        
        return script
    
    def enable(self):
        self.is_enabled = True
        
    def start(self, script):
        if self.is_enabled and not self.is_running:
            self.script = script
            self.script.on('message', self._on_message);
            self.script.load()
            self.is_running = True
            self.invalidated = False
    
    def stop(self):
        if self.is_running:
            if self.script != None:
                self.script.unload()
                self.is_running = False
    
    def disable(self):
        self.is_enabled = False
        self.stop()
        
    def is_invalidated(self):
        return self.invalidated
    
    def reload(self, script):
        self.stop()
        self.start(script)
        
    def serialize(self):
        intercept = {}
        
        intercept["addr"] = self.addr
        intercept["params"] = self.params
        intercept["ret"] = self.ret
        intercept["abi"] = self.abi
        intercept["module_name"] = self.module_name
        intercept["on_enter"] = base64.b64encode(self.onEnter)
        intercept["on_leave"] = base64.b64encode(self.onLeave)
        intercept["is_enabled"] = self.is_enabled
        
        return intercept
        
    @staticmethod
    def deserialize(intercept):
        fi = FridaIntercept(intercept["addr"], intercept["params"], intercept["ret"], intercept["module_name"], intercept["abi"])
        
        fi.onEnter = base64.b64decode(intercept["on_enter"])
        fi.onLeave = base64.b64decode(intercept["on_leave"])
        fi.is_enabled = intercept["is_enabled"]
        
        return fi
    
    @staticmethod
    def from_bn_function(function, base, module_name=None):
        addr = "0x%x" % (function.start - base)
        params = []
        for p in function.parameter_vars:
            params.append(FridaIntercept.to_frida_type(p.type))
        ret = FridaIntercept.to_frida_type(function.return_type)
        actual_addr = addr
        if "thumb" in function.platform.name:
            actual_addr = "0x%x" % ((function.start - base) + 1)
        return FridaIntercept(actual_addr, params, ret, module_name, function.calling_convention.name)
    
    @staticmethod
    def to_frida_type(bn_type):
        t = ""

        if bn_type.type_class == TypeClass.IntegerTypeClass:
            t += "int" + str(bn_type.width * 8)
            if not bn_type.signed:
                t = "u" + t
        elif bn_type.type_class == TypeClass.FloatTypeClass:
            if bn_type.width == 4:
                t = "float"
            elif bn_type_width == 8:
                t = "double"
        elif bn_type.type_class == TypeClass.PointerTypeClass:
            t = "pointer"
        elif bn_type.type_class == TypeClass.VoidTypeClass:
            t = "void"

        return t
    
    @staticmethod
    def to_frida_abi(bn_abi):
        abi = bn_abi
        
        if abi == "cdecl":
            abi = "mscdecl"
            
        return abi