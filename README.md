# rename — GDB/Pwndbg 函数重命名插件

> 修改自 _gets 佬的 rename 插件，致敬原作者 **pwngets**，感谢 gets 佬的卓越工作！

实现了在 pwndbg 中的 **func_name + offset** 显示（十进制，与 pwndbg 风格一致）。
如需十六进制显示，可在脚本中切换。

---

## 环境要求

| 组件 | 说明 |
|------|------|
| GDB + pwndbg | **pwndbg 2025.02.19+** 已适配（同时兼容旧版 2024.x 及更早版本） |
| IDA Pro | 仅 IDA 导出脚本需要 |

---

## 版本适配说明

本插件最初针对旧版 pwndbg 编写。pwndbg 在 2025.02.19 进行了重大架构重构：

- 旧 API `pwndbg.symbol.get()` / `pwndbg.gdblib.symbol.get()` **已移除**
- 新 API 为 `pwndbg.aglib.symbol.resolve_addr()`
- `pwndbg.gdblib.proc` / `pwndbg.gdblib.elf` 模块已不存在

`GDB-Import-Script.py` 现已通过三档 fallback 机制兼容所有版本：

```
pwndbg.aglib.symbol → pwndbg.gdblib.symbol → pwndbg.symbol
```

---

## 下载方法

```sh
git clone https://github.com/MindednessKind/rename.git
```

或在 Release 中分开下载。

- `IDA-Outport-Script.py` — IDA 导出函数表
- `GDB-Import-Script.py` — GDB 导入函数表

---

## 使用方法

### IDA 端

在 IDA 中重命名函数后，File → Script File 导入 `IDA-Outport-Script.py`。
如需修改导出路径，调整脚本中的 `DEFAULT_OUTPUT_PATH` 变量。

### GDB 端

```shell
# 加载插件
source ~/tools/rename/GDB-Import-Script.py

# 导入 IDA 导出的函数表
rename_import ./.rename
```

加载后可用的命令：

| 命令 | 说明 |
|------|------|
| `rename_import <file>` | 导入 .rename 文件 |
| `rename_save` | 保存当前会话的重命名到 .rename |
| `rename_load` | 从 .rename 重新加载 |
| `rename_list` | 列出所有已重命名的符号 |
| `rename_delete <addr>` | 删除指定地址的重命名 |
| `rename_uninstall` | 卸载钩子，恢复原始符号 |

---

## 效果展示

![Show](/images/Show.png)

---

## 测试环境

- Ubuntu 24 / pwndbg 2025.02.19 / Python 3.12.3

---

## 致谢

- 原作者：**pwngets**（_gets 佬）— 核心代码实现
- 适配维护：**liangbo** — pwndbg 2025.02.19+ 版本兼容适配
