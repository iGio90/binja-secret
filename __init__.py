import emu
import frida
import os
import shutil
import time
import utils

from capstone import *
from binaryninja import *
from keystone import *
from unicorn import *


session_path = os.path.dirname(os.path.realpath(__file__)) + '/session'


class SecRet(object):
    def __init__(self):
        self.frida_device = None
        self.targets = {}

        self.module_name = None
        self.frida_script = None
        self.dumps_path = ''

        self.segments_start = 0
        self.current_segments = []
        self.current_function = None
        self.current_function_address = 0
        self.current_context = {}

        self.module_base = 0
        self.module_size = 0
        self.module_tail = 0

        self.uc_arch = UC_ARCH_ARM
        self.uc_mode = UC_MODE_ARM
        self.cs_arch = CS_ARCH_ARM
        self.cs_mode = CS_MODE_ARM

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
            if parts[0] == '1':
                with open(session_path + '/context.json', 'w') as f:
                    f.write(parts[2])

                s.current_context = json.loads(parts[2])
                s.set_current_function(int(hex_addr, 16))
                s.comment_context_at_address(int(hex_addr, 16))

                s.bv.navigate('Graph:' + s.bv.view_type, int(hex_addr, 16))
            elif parts[0] == '2':
                with open(session_path + '/' + ('0x%4x' % int(parts[2], 16)), 'wb') as f:
                    f.write(payload)
                    s.add_segment(int(parts[2], 16), payload)
            elif parts[0] == '3':
                if os.path.exists(session_path):
                    shutil.rmtree(session_path)
                os.mkdir(session_path)

                s.module_base = int(parts[2], 16)
                s.module_size = int(parts[3])
                s.module_tail = s.module_base + s.module_size
                with open(session_path + '/info.json', 'w') as f:
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
        apps = sorted(apps, key=lambda x: x.name, reverse=False)
        apps_labels = []
        for app in apps:
            apps_labels.append(app.name.encode('ascii', 'ignore').decode('ascii'))
        choice_f = ChoiceField("-> spawn and attach", apps_labels)
        get_form_input([choice_f], "Target app name")
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
            shutil.rmtree(session_path)
        os.mkdir(session_path)

    def clean_segments(self, bv):
        if len(self.current_segments) > 0:
            for seg in self.current_segments:
                bv.remove_user_segment(seg.start, seg.length)
            bv.parent_view.remove(self.segments_start, len(bv.parent_view) - self.segments_start)
            self.current_segments = []
            self.segments_start = 0

    def dump_segment(self, ptr):
        print('-> trying to dump memory segment of 0x%x' % ptr)
        try:
            range_info = self.frida_script.exports.rangeinfo(ptr)
        except frida.InvalidOperationError:
            self.frida_script = None
            range_info = None
        except Exception as e:
            print('-> error while dumping memory segment from device')
            print(e)
            range_info = None

        if range_info is not None:
            data = self.frida_script.exports.dumprange(range_info['base'], range_info['size'])
            if data is not None:
                print('-> adding new segment at %s of size %u' % (range_info['base'], len(data)))
                self.add_segment(ptr, data)
                with open(session_path + '/' + ('%s' % range_info['base']), 'wb') as f:
                    f.write(data)
                s.add_segment(int(range_info['base'], 16), data)
                if self.emulator is not None:
                    self.emulator.map_segment(int(range_info['base'], 16), data)
                return 1
        return 0

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
                if self.dump_segment(ptr) == 0:
                    ptr = None
            else:
                ptr = None

        if ptr is not None:
            print('-> jumping to ' + hex(ptr))
            bv.navigate(nav_view + bv.view_type, ptr)

    def keystone_patch(self, bv, addr=0):
        input_widget = TextLineField("")
        get_form_input([input_widget], "ASM code")
        if input_widget.result is not None:
            try:
                ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
                encoding, count = ks.asm(bytes(input_widget.result), addr=addr)
                p = ''.join('{:02x}'.format(x) for x in encoding).decode('hex')
                bv.write(addr, p)
                if self.emulator is not None:
                    self.emulator.apply_patch(addr, p)
            except KsError as e:
                log_error("-> error: %s" % e)

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
        with open(session_path + '/context.json', 'r') as f:
            self.current_context = json.loads(f.read())

        with open(session_path + '/info.json', 'r') as f:
            info = json.loads(f.read())
            self.module_base = info['base']
            self.module_size = info['size']
            self.module_tail = self.module_base + self.module_size

        self.set_current_function(addr)
        self.comment_context_at_address(addr)
        for f in os.listdir(session_path):
            if f.startswith('0x'):
                with open(session_path + '/' + f, 'rb') as ff:
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

    def comment_context_at_address(self, addr, uc=None):
        regs = {}
        c = ''
        for reg in self.current_context:
            regs[utils.get_uc_reg(self.uc_arch, reg)] = reg
        for reg in sorted(regs):
            if len(c) > 0:
                c += '\n'
            if uc is None:
                c += '%s = %s' % (regs[reg].upper, self.current_context[regs[reg]])
            else:
                c += '%s = %x' % (regs[reg].upper, uc.reg_read(reg))
        self.current_function.set_comment_at(addr, c)

    def stop(self, bv):
        self.frida_device = None


s = SecRet()

PluginCommand.register_for_address('** attach **', '', s.attach)
PluginCommand.register_for_address('** restore session **', '', s.restore_session, lambda x, y: os.path.exists(session_path))
PluginCommand.register_for_address('** emulate to selected**', '', s.emulate, lambda x, y: s.current_function is not None and s.current_function_address != y)
PluginCommand.register_for_address('** emulate next**', '', s.emulate_next, lambda x, y: s.emulator is not None or s.current_function_address == y)
PluginCommand.register_for_address('** emulate selected **', '', s.emulate_instr, lambda x, y: s.current_function is not None and s.current_function_address != y)
PluginCommand.register_for_address('** instruction info **', '', s.print_instruction_info)
PluginCommand.register_for_address('** keystone patch **', '', s.keystone_patch)
PluginCommand.register_for_address('** jump to ptr **', '', s.jump_to_ptr)
