"""
Register Cross References by Ori Damari (github.com/repnz)
"""
import sark
import idaapi


def log(msg):
    idaapi.msg("[RegXref] {}\n".format(msg))


log("Plugin is loaded")


class RegisterXrefsPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Register Xrefs"
    help = "List references to a register inside a function"
    wanted_name = "RegisterXrefs"
    wanted_hotkey = "Shift+Z"

    @staticmethod
    def init():
        return idaapi.PLUGIN_OK

    @staticmethod
    def term():
        pass

    @staticmethod
    def run(_):
        run()


def PLUGIN_ENTRY():
    return RegisterXrefsPlugin()


class RegisterReferencesView(idaapi.Choose):
    def __init__(self, name, reg):
        title = 'RegisterXrefs: Function {}: xrefs to {}'.format(name, reg)
        idaapi.Choose.__init__(self, title, [["Address", 16], ["Instruction", 50]])
        self.items = []

    def add_xref(self, ea):
        text = sark.Line(ea).disasm
        hex_address = hex(ea)

        if hex_address.endswith("L"):
            hex_address = hex_address[:-1]

        self.items.append([hex_address, text])

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        address = int(self.items[n][0][2:], 16)
        idaapi.jumpto(address)

    def OnGetSize(self):
        return len(self.items)

    def show(self):
        return self.Show(modal=True) >= 0

    @staticmethod
    def make_item(reg):
        return [reg, reg]

    def OnClose(self):
        return


def has_register_reference(ins, reg_id):
    for op in ins.operands:
        for reg in op.regs:
            if get_register_identifier(reg) == reg_id:
                return True
    return False


def get_register_identifier(register_name):
    """
    In the IDA API, Every register has an ID.
    The issue is, sometimes the same register can be accessed in different sizes: For example,
    RAX, AX, AL. In IDA, the ID of the 'AX' register is different than the ID of 'AX' - this causes the cross
    reference list to be miss some references. To solve this issue, We list all the registers that have "incorrect" ID
    and translate them to other registers to get the correct ID.
    """
    register_translations = {
        'al': 'ax',
        'cl': 'cx',
        'dl': 'dx',
        'bl': 'bx',
        'ah': 'ax',
        'ch': 'cx',
        'dh': 'dx',
        'bh': 'bx',
        'spl': 'sp',
        'bpl': 'bp',
        'sil': 'si',
        'dil': 'di'
    }

    if register_name in register_translations:
        register_name = register_translations[register_name]

    return sark.get_register_id(register_name)


def run():
    try:
        current_function = sark.Function()
    except sark.exceptions.SarkNoFunction:
        log("Cannot xref registers outside of functions.")
        return

    register_name = idaapi.get_highlighted_identifier()

    try:
        register_id = get_register_identifier(register_name)
    except sark.exceptions.SarkInvalidRegisterName:
        log("Highlight a register to xref")
        return

    choose = RegisterReferencesView(current_function.name, register_name)

    for line in current_function.lines:
        if has_register_reference(line.insn, register_id):
            choose.add_xref(line.ea)

    choose.show()
