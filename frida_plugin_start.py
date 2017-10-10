from frida_plugin import FridaPlugin

from binaryninja import *
import frida

class FridaPluginStart(FridaPlugin):
    def __init__(self, settings):
        super(FridaPluginStart, self).__init__(settings)
    
    def run(self, bv, function=None):
        frida_devices = frida.enumerate_devices()
        try:
            last_device = bv.query_metadata("frida_plugin_device_id")
        except KeyError:
            last_device = self.settings.get_string("device_id")

        devices = []
        device_reorder = []
        for device in frida_devices:
            if device.id == last_device:
                devices.insert(0, device.name)
                device_reorder.insert(0, device)
            else:
                devices.append(device.name)
                device_reorder.append(device)
        choice_f = ChoiceField("Devices", devices)
        get_form_input([choice_f], "Get Frida Device")
        if choice_f.result != None:
            self.settings.set_string("device_id", device_reorder[choice_f.result].id)
            bv.store_metadata("frida_plugin_device_id", str(device_reorder[choice_f.result].id))
            self.frida_device = device_reorder[choice_f.result]