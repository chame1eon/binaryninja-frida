'''
Tested on Python 3.8, Linux, Binary Ninja 2.0.2170, Frida 12.9.4
'''
from .frida_plugin import FridaPlugin

from binaryninja import *
import os
import frida


class FridaPluginStartAttach(FridaPlugin):
    '''Purpose is to allow user to specify a binary file to spawn as a new
    process and have frida attach to it.
    '''
    def __init__(self, settings):
        super(FridaPluginStartAttach, self).__init__(settings)
        self.binary_name = None

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

            # Generate ui text input
            cmd_line = TextLineField('Command line')
            ret = get_form_input([cmd_line], "Start Process")

            if not ret:
                log.log_info("No binary to spawn specified.")
                return

            self.binary_name = cmd_line.result
            frida_pid = device.spawn(self.binary_name)
            log.log_info(f'Spawned process pid: {frida_pid}')
            self.frida_session = device.attach(frida_pid)

            self.settings.set_string("frida.process_name", self.binary_name)
            bv.store_metadata("frida_plugin_process_name", self.binary_name)
            log.log_info(f'{self.binary_name}')
            log.log_info("Frida Plugin: Successfully connected to device.")
            filename = os.path.split(bv.file.filename)[-1].split('.')[0]
            self.module_name = filename

            log.log_info(f'Applying intercepts {filename}')

            for addr, intercept in list(self.intercepts.items()):
                log.log_debug(f'Intercept debug: {intercept.to_frida_script()}')
                if intercept.is_enabled:
                    intercept.set_module_name(self.module_name)
                    intercept.start(self.frida_session.create_script(intercept.to_frida_script()))

            device.resume(frida_pid)

        else:
            log.log_error("Frida Plugin: No device set. Please select from tools menu.")
