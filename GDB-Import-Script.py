import gdb
import argparse
import pwndbg.commands
import subprocess
import os

try:
    import pwndbg.aglib.symbol as symbol
except ImportError:
    try:
        import pwndbg.gdblib.symbol as symbol
    except ImportError:
        import pwndbg.symbol as symbol

# PIE/进程 API 兼容层
try:
    import pwndbg.aglib.proc as _proc_mod
    import pwndbg.aglib.elf as _elf_mod
    _HAS_AGLIB_PROC = True
except Exception:
    _HAS_AGLIB_PROC = False

def _binary_base_addr():
    """兼容 pwndbg 2025.02.19 (property) 与 2026.02.18 (function) 两种 API 形态"""
    attr = _proc_mod.binary_base_addr
    return attr() if callable(attr) else attr

def _proc_exe():
    attr = _proc_mod.exe
    return attr() if callable(attr) else attr

# 命令注册兼容不同 pwndbg 版本
# 2025.02.19 及更早: 有 ArgparsedCommand，裸 @Command 装饰器 lex_args 按位置传参
# 2026.02.18+: ArgparsedCommand 已合并进 Command，需 category 与显式 ArgumentParser
if hasattr(pwndbg.commands, 'ArgparsedCommand'):
    _cmd_reg = pwndbg.commands.Command
else:
    from pwndbg.commands import CommandCategory
    import inspect
    def _cmd_reg(func):
        sig = inspect.signature(func)
        parser = argparse.ArgumentParser(description=func.__name__.replace("_", " "))
        for name, param in sig.parameters.items():
            if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                continue
            if param.default is inspect.Parameter.empty:
                parser.add_argument(name, type=str, help=name)
            else:
                parser.add_argument(name, nargs="?", type=str, default=param.default,
                                    help=name)
        return pwndbg.commands.Command(parser, category=CommandCategory.MISC)(func)

#用来缓存pie地址与pie是否开启，无需每次都调用命令
pie_addr : int|None = None
is_pie_enabled : bool|None = None

# 存储用户的符号和断点
user_symbols = {}
user_breakpoints = {}
user_orig_addrs = {}       # 记录原始文件偏移地址，用于 rename-save

# 保存原始的 resolve_addr 方法
original_resolve_addr = symbol.resolve_addr

# 文件路径
SAVE_FILE = './rename.txt'

# 重新定义解析地址的方法，支持偏移显示
def renamed_resolve_addr(address):
    if address in user_symbols:
        name = user_symbols[address]
        if '+' in name:
            function_name, offset = name.split('+')
            return f"{function_name}+{offset}"
        return name
    return original_resolve_addr(address)

# 安装和卸载符号钩子
def install_hook():
    symbol.resolve_addr = renamed_resolve_addr

def uninstall_hook():
    symbol.resolve_addr = original_resolve_addr
    user_symbols.clear()
    user_breakpoints.clear()
    user_orig_addrs.clear()

# 检查是否为PIE（位置无关执行文件）
def is_pie():
    global is_pie_enabled
    if is_pie_enabled is not None:
        return is_pie_enabled

    if _HAS_AGLIB_PROC:
        try:
            is_pie_enabled = _elf_mod.get_elf_info(_proc_exe()).is_pie
            return is_pie_enabled
        except Exception:
            pass

    try:
        result = subprocess.run(['checksec', '--fortify-file', '--pie'],
                                capture_output=True, text=True)
        if "No PIE" not in result.stdout:
            is_pie_enabled = True
            return True
    except FileNotFoundError:
        print("[!] checksec not found, cannot verify PIE status.")
    is_pie_enabled = False
    return False

# 获取PIE基址
def get_pie_base():
    global pie_addr
    if not is_pie():
        return 0
    if pie_addr is not None:
        return pie_addr

    if _HAS_AGLIB_PROC:
        try:
            pie_addr = _binary_base_addr()
            return pie_addr
        except Exception:
            pass

    try:
        result = gdb.execute('piebase', to_string=True).strip()
        if result:
            import re
            match = re.search(r'0x[0-9a-fA-F]+', result)
            if match:
                pie_addr = int(match.group(0), 16)
                return pie_addr
    except gdb.error:
        print("[!] Error: Unable to retrieve PIE base address.")
    return 0

# 修复地址（考虑PIE基址）
def fix_address(addr):
    if _HAS_AGLIB_PROC:
        try:
            base = _binary_base_addr()
            if addr < base:
                return addr + base
            return addr
        except Exception:
            pass

    pie_base = get_pie_base()
    if pie_base:
        if addr >= pie_base:
            return addr
        return addr + pie_base
    return addr

# 获取绝对地址（与 fix_address 逻辑一致）
get_absolute_address = fix_address

# 导入符号并显示带偏移的符号
@_cmd_reg
def rename_import(file):
    try:
        with open(file, 'r') as f:
            for line in f:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.strip().split()
                
                #小于2 parts，不合法，直接返回
                if len(parts) < 2:
                    print(f'[!] Invalid line: {line.strip()}')
                    continue
                
                #根据parts数量选择分支处理
                if len(parts) == 2:                             #for addr+name format
                    addr_str, name = parts[0], parts[1]
                    orig_addr = int(addr_str, 0)
                    addr = fix_address(orig_addr)
                    user_symbols[addr] = name
                    user_orig_addrs[addr] = orig_addr
                    print(f"✓ imported {name} at {addr:#x}")
                # 设置断点
                elif len(parts) == 3 and parts[2] == '#bp':     #for addr+name+"#bp" format
                    addr_str, name = parts[0], parts[1]
                    orig_addr = int(addr_str, 0)
                    addr = fix_address(orig_addr)
                    abs_addr = get_absolute_address(addr)
                    gdb.execute(f'b *{hex(abs_addr)}')
                    user_symbols[addr] = name
                    user_breakpoints[addr] = name
                    user_orig_addrs[addr] = orig_addr
                    print(f'✓ Breakpoint set at {name} (address 0x{abs_addr:x})')
                elif len(parts) == 3 and parts[2] != '#bp':     #for start_str+end_str+name format
                    start_str, end_str, name = parts[0], parts[1], parts[2]
                    orig_start = int(start_str, 0)
                    start = fix_address(orig_start)
                    end = fix_address(int(end_str, 0))
                    for a in range(start, end):
                        user_symbols[a] = f"{name}+{a - start}" # 10 进制显示方法
                        user_orig_addrs[a] = orig_start + (a - start)
                    user_symbols[start] = name
                    user_orig_addrs[start] = orig_start
                    print(f"✓ imported {name} ({start:#x} - {end:#x})")
                else:
                    print(f"[!] Invalid line format: {line}")
    except Exception as e:
        print(f'[!] Failed to import: {e}')

# 保存符号重命名
@_cmd_reg
def rename_save():
    try:
        with open(SAVE_FILE, 'w') as f:
            for addr, name in user_symbols.items():
                orig = user_orig_addrs.get(addr, addr)
                f.write(f'0x{orig:x} {name}\n')
        print(f'✓ Saved to {SAVE_FILE}')
    except Exception as e:
        print(f'[!] Failed to save: {e}')

# 加载符号重命名
@_cmd_reg
def rename_load():
    if not os.path.exists(SAVE_FILE):
        print(f'[!] {SAVE_FILE} not found')
        return
    rename_import(SAVE_FILE)

# 显示重命名的符号
@_cmd_reg
def rename_list():
    if not user_symbols:
        print('No renamed symbols.')
        return
    for addr, name in sorted(user_symbols.items()):
        breakpoint_status = 'with breakpoint' if addr in user_breakpoints else 'no breakpoint'
        print(f'0x{addr:x}: {name} ({breakpoint_status})')

# 删除符号重命名
@_cmd_reg
def rename_delete(addr):
    try:
        addr = int(addr, 0)
        addr = fix_address(addr)
        if addr in user_symbols:
            del user_symbols[addr]
            user_orig_addrs.pop(addr, None)
            if addr in user_breakpoints:
                gdb.execute(f'clear {user_breakpoints[addr]}')
                del user_breakpoints[addr]
            print(f'✓ Deleted rename for 0x{addr:x}')
        else:
            print(f'[!] No rename for 0x{addr:x}')
    except Exception as e:
        print(f'[!] Failed to delete: {e}')

# 卸载钩子
@_cmd_reg
def rename_uninstall():
    uninstall_hook()
    print('Rename hooks uninstalled.')

# 安装符号钩子
install_hook()
