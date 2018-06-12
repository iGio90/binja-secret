import emu
import frida
import os
import shutil
import time

from binaryninja import *

session_path = os.path.dirname(os.path.realpath(__file__)) + '/session'


class SecRet(object):
    def __init__(self):
        self.frida_device = None
        self.targets = {}

        self.module_name = None
        self.frida_script = None

        self.segments_start = 0
        self.current_segments = []
        self.current_function = None
        self.current_function_address = 0
        self.current_context = {}

        self.module_base = 0
        self.module_size = 0
        self.module_tail = 0

        self.bv = None
        self.emulator = None

    @staticmethod
    def _on_frida_message(message, payload):
        if 'payload' in message:
            parts = str(message['payload']).split(":::")
            if parts[1].startswith('0x'):
                hex_addr = parts[1]
            else:
                hex_addr = '0x%4x' % int(parts[1])
            dumps_path = session_path + '/' + hex_addr
            if parts[0] == '1':
                with open(dumps_path + '/context.json', 'w') as f:
                    f.write(parts[2])

                s.set_current_function(int(hex_addr, 16))
                s.current_context = json.loads(parts[2])

                s.bv.navigate('Graph:' + s.bv.view_type, int(hex_addr, 16))
            elif parts[0] == '2':
                with open(dumps_path + '/' + ('0x%4x' % int(parts[2], 16)), 'wb') as f:
                    f.write(payload)
                    s.add_segment(int(parts[2], 16), payload)
            elif parts[0] == '3':
                if os.path.exists(dumps_path):
                    shutil.rmtree(dumps_path)
                os.mkdir(dumps_path)

                s.module_base = int(parts[2], 16)
                s.module_size = int(parts[3])
                s.module_tail = s.module_base + s.module_size
                with open(dumps_path + '/info.json', 'w') as f:
                    f.write(json.dumps({'base': s.module_base, 'size': s.module_size}))
        else:
            print(message)

    def add_segment(self, offset, payload):
        new_data_offset = len(self.bv.parent_view)
        if self.segments_start == 0:
            self.segments_start = new_data_offset
        self.bv.parent_view.insert(new_data_offset, payload)
        self.bv.add_user_segment(offset, len(payload), new_data_offset, len(payload), 7)

        segment = self.bv.get_segment_at(offset)
        self.current_segments.append(segment)

    def attach(self, bv, address=0):
        self.bv = bv
        self.clean_session()

        self.frida_device = frida.get_usb_device(5)

        if self.module_name is None:
            input_widget = TextLineField("")
            get_form_input([input_widget], "Target module name")
            if input_widget.result is not None:
                self.module_name = input_widget.result
                if not self.module_name.endswith('.so'):
                    self.module_name += '.so'
            else:
                log_error('-> module name cannot be empty')
                return

        print('-> target module: ' + self.module_name)
        time.sleep(1)

        apps = self.frida_device.enumerate_applications()
        apps_labels = []
        for app in apps:
            apps_labels.append(app.name.encode('ascii', 'ignore').decode('ascii'))
        choice_f = ChoiceField("Apps", apps_labels)
        get_form_input([choice_f], "Select application to spawn")
        if choice_f.result is not None:
            package_name = apps[choice_f.result].identifier
            pid = self.frida_device.spawn([package_name])
            process = self.frida_device.attach(pid)
            print("-> Frida attached.")
            import script
            self.frida_script = process.create_script(script.get_script(self.module_name, '0x%4x' % address))
            print("-> Script loaded.")
            self.frida_device.resume(package_name)
            self.frida_script.on('message', self._on_frida_message)
            self.frida_script.load()

    def clean_session(self):
        self.set_current_function(0)
        if os.path.exists(session_path):
            if self.bv is not None:
                self.clean_segments(self.bv)
                for f in os.listdir(session_path):
                    if f.startswith('0x'):
                        function = self.bv.get_functions_containing(int(f, 16))[0]
                        function.set_auto_instr_highlight(int(f, 16), HighlightStandardColor.NoHighlightColor)

            shutil.rmtree(session_path)
        os.mkdir(session_path)

    def clean_segments(self, bv):
        if len(self.current_segments) > 0:
            for seg in self.current_segments:
                bv.remove_user_segment(seg.start, seg.length)
            bv.parent_view.remove(self.segments_start, len(bv.parent_view) - self.segments_start)
            self.current_segments = []
            self.segments_start = 0

    def emulate(self, bv, addr=0):
        if self.emulator is None:
            self.emulator = emu.Emu(self, bv, addr)
        self.emulator.start(addr)

    def emulate_instr(self, bv, addr=0):
        if self.emulator is None:
            self.emulator = emu.Emu(self, bv, addr)
        self.emulator.emulate_instr(addr)

    def emulate_next(self, bv, addr=0):
        if self.emulator is None:
            self.emulator = emu.Emu(self, bv, addr)
        self.emulator.emulate_next()

    def jump_to_ptr(self, bv, addr=0):
        br = BinaryReader(bv)
        br.seek(addr)
        ptr = br.read32le()
        nav_view = 'Hex:'
        if 0 < self.module_base < ptr < self.module_base + self.module_size:
            ptr = ptr - self.module_base
            nav_view = 'Graph:'
        if not bv.is_valid_offset(ptr):
            if self.frida_script is not None:
                print('-> trying to dump memory segment of ' + hex(ptr))
                data = self.frida_script.exports.dumprange(ptr)
                if data is None or len(data) == 0:
                    ptr = None
                else:
                    self.add_segment(ptr, data)
            else:
                ptr = None

        if ptr is not None:
            print('-> jumping to ' + hex(ptr))
            bv.navigate(nav_view + bv.view_type, ptr)

    def print_instruction_info(self, bv, addr=0):
        try:
            funct = bv.get_functions_containing(addr)[0]
        except:
            print(('0x%.8x' % addr) + ' -> no functions found')
            return

        print(('0x%.8x' % addr) + ' -> instructions info')
        print(funct.get_low_level_il_at(addr))
        print(funct.get_regs_read_by(addr))
        print(funct.get_regs_written_by(addr))
        print(funct.get_call_stack_adjustment(addr))
        print(funct.get_lifted_il_at(addr))

    def restore_session(self, bv, addr):
        self.bv = bv
        self.emulator = None
        self.clean_segments(bv)
        dumps_path = session_path + ('/0x%4x' % addr)
        with open(dumps_path + '/context.json', 'r') as f:
            self.current_context = json.loads(f.read())

        with open(dumps_path + '/info.json', 'r') as f:
            info = json.loads(f.read())
            self.module_base = info['base']
            self.module_size = info['size']
            self.module_tail = self.module_base + self.module_size

        self.set_current_function(addr)
        for f in os.listdir(dumps_path):
            if f.startswith('0x'):
                with open(dumps_path + '/' + f, 'rb') as ff:
                    self.add_segment(int(f, 16), ff.read())

    def set_current_function(self, addr):
        self.current_function_address = addr
        if self.current_function is not None:
            self.current_function.set_auto_instr_highlight(addr, HighlightColor(red=0x59, blue=0xb3, green=0x00))
        if self.bv is not None:
            l = self.bv.get_functions_containing(addr)
            if l is not None and len(l) > 0:
                self.current_function = l[0]
                self.current_function.set_auto_instr_highlight(addr, HighlightColor(red=0xb3, blue=0x00, green=0x00))
            else:
                self.current_function = None
        else:
            self.current_function = None

    def stop(self, bv):
        self.frida_device = None


s = SecRet()

PluginCommand.register_for_address('** attach **', '', s.attach)
PluginCommand.register_for_address('** restore session **', '', s.restore_session, lambda x, y: os.path.exists(session_path + ('/0x%4x' % y)))
PluginCommand.register_for_address('** emulate **', '', s.emulate, lambda x, y: s.current_function is not None and s.current_function_address != y)
PluginCommand.register_for_address('** emulate next **', '', s.emulate_next, lambda x, y: s.emulator is not None or s.current_function_address == y)
PluginCommand.register_for_address('** emulate instruction **', '', s.emulate_instr, lambda x, y: s.current_function is not None and s.current_function_address != y)
PluginCommand.register_for_address('** instruction info **', '', s.print_instruction_info)
PluginCommand.register_for_address('** jump to ptr **', '', s.jump_to_ptr)
