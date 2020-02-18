import sys

from binaryninja import *

from .frida_plugin_start import FridaPluginStart
from .frida_plugin_attach import FridaPluginAttach
from .frida_plugin_stop import FridaPluginStop
from .frida_plugin_intercept import FridaPluginIntercept
from .frida_plugin_modify import FridaPluginModify
from .frida_plugin_remove import FridaPluginRemove
from .frida_plugin_reload import FridaPluginReload

intercepts = {}
settings = Settings("binaryninja-frida")
settings.register_group("frida", "Frida Settings")
settings.register_setting("frida.device_id", '{"description" : "Currently selected device id.", "title" : "Frida Device ID", "default" : "", "type" : "string"}')
settings.register_setting("frida.process_name", '{"description" : "Currently selected process name", "title" : "Frida Selected Process Name", "default" : "", "type" : "string"}')


plugin_commands = [
    {
        "title": "Frida: Start Plugin",
        "desc": "",
        "plugin_module": FridaPluginStart(settings),
        "type": "main"
    },
    {
        "title": "Frida: Attach to Process",
        "desc": "",
        "plugin_module": FridaPluginAttach(settings),
        "type": "main"
    },
    {
        "title": "Frida: Stop Plugin",
        "desc": "",
        "plugin_module": FridaPluginStop(settings),
        "type": "main"
    },
    {
        "title": "Frida: Intercept Function",
        "desc": "",
        "plugin_module": FridaPluginIntercept(settings),
        "type": "function"
    },
    {
        "title": "Frida: Remove Function Intercept",
        "desc": "",
        "plugin_module": FridaPluginRemove(settings),
        "type": "function"
    },
    {
        "title": "Frida: Modify Intercept",
        "desc": "",
        "plugin_module": FridaPluginModify(settings),
        "type": "function"
    },
    {
        "title": "Frida: Reload",
        "desc": "",
        "plugin_module": FridaPluginReload(settings),
        "type": "main"
    }
]

for c in plugin_commands:
    title = c["title"]
    desc = c["desc"]
    plugin_module = c["plugin_module"]
    t = c["type"]
    if t == "main":
        PluginCommand.register(title, desc, plugin_module._run, plugin_module._is_valid)
    elif t == "function":
        PluginCommand.register_for_function(title, desc, plugin_module._run, plugin_module._is_valid)
