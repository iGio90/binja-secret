from binaryninja import *
from capstone import *
from unicorn import *
from unicorn.arm_const import *

import utils


class Emu(object):
    def __init__(self, s, bv, ep):
        self._secret = s
        self._bv = bv

        self.uc_arch = UC_ARCH_ARM
        self.uc_mode = UC_MODE_ARM

        self.entry = self._secret.module_base + self._secret.current_function_address
        self.exit = self._secret.module_base + ep
        if self.uc_mode == UC_MODE_THUMB:
            self.entry = self.entry | 1
            self.exit = self.exit | 1

        self.uc = Uc(self.uc_arch, self.uc_mode)
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.md.detail = True

        self.current_address = self._secret.current_function_address
        self.current_virtual_address = self.entry

        self.break_steps = 0
        self.previous_instr_info = {
            'address': 0,
            'virtual_address': 0,
            'regs': []
        }

        self.mapped_segment = {}
        self._context_setup()

    def apply_patch(self, addr, patch):
        self.uc.mem_write(addr + self._secret.module_base, patch)

    def _context_setup(self):
        stlist = sorted(self._bv.segments, key=lambda x: x.start, reverse=False)
        for segment in stlist:
            if segment.start < self._secret.module_size:
                # assuming frida will dump target module we will have it mapped later
                continue
            print('-> segment start at 0x%x' % segment.start)
            self.map_segment(segment.start, self._bv.read(segment.start, segment.length))

        self.uc.reg_write(UC_ARM_REG_R0, int(self._secret.current_context['r0'], 16))
        self.uc.reg_write(UC_ARM_REG_R1, int(self._secret.current_context['r1'], 16))
        self.uc.reg_write(UC_ARM_REG_R2, int(self._secret.current_context['r2'], 16))
        self.uc.reg_write(UC_ARM_REG_R3, int(self._secret.current_context['r3'], 16))
        self.uc.reg_write(UC_ARM_REG_R4, int(self._secret.current_context['r4'], 16))
        self.uc.reg_write(UC_ARM_REG_R5, int(self._secret.current_context['r5'], 16))
        self.uc.reg_write(UC_ARM_REG_R6, int(self._secret.current_context['r6'], 16))
        self.uc.reg_write(UC_ARM_REG_R7, int(self._secret.current_context['r7'], 16))
        self.uc.reg_write(UC_ARM_REG_R8, int(self._secret.current_context['r8'], 16))
        self.uc.reg_write(UC_ARM_REG_R9, int(self._secret.current_context['r9'], 16))
        self.uc.reg_write(UC_ARM_REG_R10, int(self._secret.current_context['r10'], 16))
        self.uc.reg_write(UC_ARM_REG_R11, int(self._secret.current_context['r11'], 16))
        self.uc.reg_write(UC_ARM_REG_R12, int(self._secret.current_context['r12'], 16))
        self.uc.reg_write(UC_ARM_REG_SP, int(self._secret.current_context['sp'], 16))
        self.uc.reg_write(UC_ARM_REG_PC, int(self._secret.current_context['pc'], 16))
        self.uc.reg_write(UC_ARM_REG_LR, int(self._secret.current_context['lr'], 16))

        self.uc.hook_add(UC_HOOK_CODE, self.hook_instr)
        self.uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, self.hook_mem_access)

    def map_segment(self, address, data):
        data_len = len(data)
        map_base = 1024 * 1024 * (((address / 1024) / 1024) - 1)
        map_base = map_base & 0xff000000

        while '0x%x' % map_base in self.mapped_segment:
            map_base += 0xffffff + 1

        if map_base > address + data_len:
            print('-> writing an already mapped segment at 0x%x' % address)
            self.uc.mem_write(address, data)
        else:
            map_tail = map_base + 0xffffff + 1
            self.mapped_segment['0x%x' % map_base] = 1

            while address + data_len > map_tail:
                if '0x%x' % map_tail in self.mapped_segment:
                    break
                self.mapped_segment['0x%x' % map_tail] = 1
                map_tail += 0xffffff + 1

            print('-> mapping 0x%x at 0x%x' % (map_tail - map_base, map_base))
            self.uc.mem_map(map_base, map_tail - map_base)
            self.uc.mem_write(address, data)

    def parse_address(self, address):
        if self._secret.module_base < address < self._secret.module_tail:
            return address - self._secret.module_base
        return address

    def hook_instr(self, uc, address, size, user_data):
        parsed_address = self.parse_address(address)

        if self.break_steps > 0:
            if self.break_steps == 2:
                uc.emu_stop()
                self.break_steps = 0
                self.set_current_address(parsed_address, None, False)
                return
            self.break_steps += 1

        if self.previous_instr_info['address'] > 0:
            c = '\n'
            for r in self.previous_instr_info['regs']:
                c += '\n%s 0x%x' % (r['r'], uc.reg_read(r['o']))
            self.append_comment(c, self.previous_instr_info['address'])

        self.previous_instr_info['address'] = parsed_address
        self.previous_instr_info['virtual_address'] = address
        op = {}
        print("-> Tracing instruction at 0x%x (0x%x), instruction size = 0x%x" % (parsed_address, address, size))
        for i in self.md.disasm(bytes(uc.mem_read(address, size)), address):
            print("0x%x:\t%s\t%s" % (parsed_address, i.mnemonic, i.op_str))
            if len(i.operands) > 0:
                for o in i.operands:
                    try:
                        s = i.reg_name(o.value.reg).upper()
                        if s == '(INVALID)':
                            continue
                        op[s] = ''
                    except:
                        continue
        self.previous_instr_info['regs'] = []
        c = ''
        for reg in op:
            if len(c) > 0:
                c += '\n'
            uc_reg = getattr(utils.get_arch_consts(self.uc_arch), utils.get_reg_tag(self.uc_arch) + reg)
            c += reg + ' = ' + ('0x%x' % uc.reg_read(uc_reg))
            self.previous_instr_info['regs'].append({'r': reg, 'o': uc_reg})
        self.set_current_address(parsed_address, c)

    def set_current_address(self, addr, comment=None, hightlight=True):
        self.current_address = addr
        self.current_virtual_address = addr + self._secret.module_base
        try:
            function = self._bv.get_functions_containing(addr)[0]
            if hightlight:
                function.set_auto_instr_highlight(addr, HighlightColor(red=0x60, blue=0xc3, green=0x6e))
            if comment is not None:
                function.set_comment_at(addr, comment)
            self._bv.navigate('Graph:' + self._bv.view_type, addr)
        except:
            try:
                if self._bv.is_valid_offset(addr):
                    self._bv.navigate('Graph:' + self._bv.view_type, addr)
            except:
                print('-> set current address: failed to read at 0x%x' % addr)

    def append_comment(self, addr, c):
        try:
            function = self._bv.get_functions_containing(addr)[0]
            oc = function.get_comment_at(addr)
            if oc is None:
                oc = ''
            oc += c
            function.set_comment_at(addr, oc)
        except:
            pass

    def hook_mem_access(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            print("-> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
            try:
                function = self._bv.get_functions_containing(self.current_address)[0]
                c = function.get_comment_at(self.current_address)
                cc = ('\n\n*0x%x = 0x%x' % (address, value))
                if c is not None:
                    c += cc
                else:
                    c = cc
                function.set_comment_at(self.current_address, c)
            except:
                pass
        else:
            try:
                print("-> Memory is being READ at 0x%x, data size = %u, data value = 0x%x"
                      % (address, size, int(self._bv.read(address, size).encode('hex'), 16)))
            except:
                print('-> hook mem access: failed to read at 0x%x' % address)
                if self._secret.frida_script is not None:
                    self._secret.dump_segment(address)

    def start(self, exit=0):
        if exit > 0:
            self.exit = self._secret.module_base + exit
        self._start_emu(self.current_virtual_address, self.exit)

    def emulate_instr(self, addr):
        self.current_address = addr
        self.current_virtual_address = self._secret.module_base + addr
        self.emulate_next()

    def emulate_next(self):
        self.break_steps = 1
        self._start_emu(self.current_virtual_address, self.current_virtual_address + 8)

    def _start_emu(self, s, e):
        try:
            print('-> emulation started at 0x%x (0x%x)' % (s, self.parse_address(s)))
            self.uc.emu_start(s, e)
        except Exception as e:
            self.uc.emu_stop()
            print('-> emu error: %s' % e)
