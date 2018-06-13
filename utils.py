from unicorn import *


def get_arch_consts(arch):
    if arch == UC_ARCH_ARM:
        return arm_const
    elif arch == UC_ARCH_ARM64:
        return arm64_const
    elif arch == UC_ARCH_M68K:
        return m68k_const
    elif arch == UC_ARCH_MIPS:
        return mips_const
    elif arch == UC_ARCH_SPARC:
        return sparc_const
    elif arch == UC_ARCH_X86:
        return x86_const


def get_reg_tag(arch):
    if arch == UC_ARCH_ARM:
        return "UC_ARM_REG_"
    elif arch == UC_ARCH_ARM64:
        return "UC_ARM64_REG_"
    elif arch == UC_ARCH_M68K:
        return "UC_M68K_REG_"
    elif arch == UC_ARCH_MIPS:
        return "UC_MIPS_REG_"
    elif arch == UC_ARCH_SPARC:
        return "UC_SPARC_REG_"
    elif arch == UC_ARCH_X86:
        return "UC_X86_REG_"


def get_uc_reg(arch, reg):
    return getattr(get_arch_consts(arch), get_reg_tag(arch) + reg.upper())
