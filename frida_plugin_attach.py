from .frida_plugin import FridaPlugin

from binaryninja import *
import os
import frida

class FridaPluginAttach(FridaPlugin):
    def __init__(self, settings):
        super(FridaPluginAttach, self).__init__(settings)

    def is_valid(self, bv, function=None):
        return self.frida_device != None

    def run(self, bv, function=None):
        device_id = self.settings.get_string("frida.device_id")
        if device_id:
            device = None
            try:
                device = frida.get_device(device_id, timeout=3)
            except frida.TimedOutError:
                log.log_error("Frida Plugin: Failed to find device. Please try reconnecting device or select another from the device menu.")
                return

            frida_processes = device.enumerate_processes()
            try:
                last_process = bv.query_metadata("frida_plugin_process_name")
            except KeyError:
                last_process = self.settings.get_string("frida.process_name")

            processes = []
            processes_reorder = []
            for process in frida_processes:
                if process.name == last_process:
                    processes.insert(0, f'{process.name}-{process.pid}')
                    processes_reorder.insert(0, process)
                else:
                    processes.append(f'{process.name}-{process.pid}')
                    processes_reorder.append(process)
            choice_f = ChoiceField("Processes", processes)
            get_form_input([choice_f], "Attach Frida to Process")
            if choice_f.result != None:
                self.settings.set_string("frida.process_name", processes_reorder[choice_f.result].name)
                bv.store_metadata("frida_plugin_process_name", str(processes_reorder[choice_f.result].name))
                process = processes_reorder[choice_f.result]
                self.frida_session = device.attach(process.pid)
                log.log_info("Frida Plugin: Successfully connected to device.")
                filename = os.path.split(bv.file.filename)[-1].split('.')[0] + '.'
                self.module_name = filename

                for addr, intercept in list(self.intercepts.items()):
                    if intercept.is_enabled:
                        intercept.set_module_name(self.module_name)
                        intercept.start(self.frida_session.create_script(intercept.to_frida_script()))
        else:
            log.log_error("Frida Plugin: No device set. Please select from tools menu.")
