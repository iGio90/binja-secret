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

        self.current_address = 0

        self.break_steps = 0

        self._context_setup()

    def _context_setup(self):
        last_mapped_off = 0

        print('base 0x%x - len 0x%x' % (self._secret.module_base, self._secret.module_size))
        map_base = 1024 * 1024 * (((self._secret.module_base / 1024) / 1024) - 1)
        map_size = 1024 * 1024 * (((self._secret.module_size / 1024) / 1024) + 1)
        self.uc.mem_map(map_base, map_size)
        self.uc.mem_write(self._secret.module_base, self._bv.read(0, self._secret.module_size))

        stlist = sorted(self._bv.segments, key=lambda x: x.start, reverse=False)
        for segment in stlist:
            if segment.start < self._secret.module_size:
                continue

            map_base = 1024 * 1024 * (((segment.start / 1024) / 1024) - 1)
            if map_base < 0:
                map_base = 0
            map_size = 1024 * 1024 * (((segment.length / 1024) / 1024) + 1)
            if map_base < last_mapped_off:
                map_base = last_mapped_off
            last_mapped_off = map_base + map_size
            print('-> mapping ' + str(map_size) + ' at ' + hex(map_base))
            while segment.start + segment.length > last_mapped_off:
                map_size += 1024
                last_mapped_off += 1024

            self.uc.mem_map(map_base, map_size)
            self.uc.mem_write(segment.start, self._bv.read(segment.start, segment.length))

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
                self.set_current_bv_address(parsed_address, None, False)
                return
            self.break_steps += 1

        print("-> Tracing instruction at 0x%x, instruction size = 0x%x" % (parsed_address, size))
        op = {}
        for i in self.md.disasm(bytes(uc.mem_read(address, size)), address):
            print("0x%x:\t%s\t%s" % (parsed_address, i.mnemonic, i.op_str))
            if len(i.regs_read) > 0:
                print("\tImplicit registers read: "),
                for r in i.regs_read:
                    print("%s " % i.reg_name(r)),

            if len(i.operands) > 0:
                for o in i.operands:
                    try:
                        s = i.reg_name(o.value.reg).upper()
                        if s == '(INVALID)':
                            continue
                        op[s] = ''
                    except:
                        continue
        c = ''
        for reg in op:
            if len(c) > 0:
                c += '\n'
            c += reg + ' = ' + ('0x%x' % uc.reg_read(
                getattr(utils.get_arch_consts(self.uc_arch), utils.get_reg_tag(self.uc_arch) + reg)))
        self.set_current_bv_address(parsed_address, c)

    def set_current_bv_address(self, addr, comment=None, hightlight=True):
        self.current_address = addr
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

    def start(self, exit=0):
        if exit > 0:
            self.exit = self._secret.module_base + exit
        self._start_emu(self.entry, self.exit)

    def emulate_instr(self, addr):
        self.current_address = self._secret.module_base + addr
        self.emulate_next()

    def emulate_next(self):
        self.break_steps = 1
        if self.current_address == 0:
            self.current_address = self.entry
        self._start_emu(self.current_address, self.current_address + 8)

    def _start_emu(self, s, e):
        try:
            self.uc.emu_start(s, e)
        except Exception as e:
            self.uc.emu_stop()
            print('-> emu error:')
            print(e)
