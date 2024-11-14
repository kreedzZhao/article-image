import lief
import sys
import random


def log_color(msg):
    print(f"\033[1;31;40m{msg}\033[0m")


def replace_in_binary_file(input_file, old_string, new_string):
    # 以二进制模式读取文件内容
    with open(input_file, 'rb') as file:
        data = file.read()

    # 将旧的字节串替换为新的字节串
    data = data.replace(old_string.encode(), new_string.encode())

    # 以二进制模式写回文件内容
    with open(input_file, 'wb') as file:
        file.write(data)


set_all_str = set()

if __name__ == "__main__":
    input_file = sys.argv[1]
    random_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    log_color(f"[*] Patch frida-agent: {input_file}")
    binary = lief.parse(input_file)

    if not binary:
        log_color(f"[*] Not elf, exit")
        exit()

    random_name = "".join(random.sample(random_charset, 5))
    log_color(f"[*] Patch `frida` to `{random_name}`")

    for symbol in binary.symbols:
        if symbol.name == "frida_agent_main":
            symbol.name = "main"

        if "frida" in symbol.name:
            symbol.name = symbol.name.replace("frida", random_name)

        if "FRIDA" in symbol.name:
            symbol.name = symbol.name.replace("FRIDA", random_name)

        set_all_str.add(symbol.name)

    all_patch_string = ["FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript"]  # 字符串特征修改 尽量与源字符一样
    for section in binary.sections:
        if section.name != ".rodata":
            continue
        for patch_str in all_patch_string:
            addr_all = section.search_all(patch_str)  # Patch 内存字符串
            for addr in addr_all:
                patch_values = "".join(random.sample(random_charset, len(patch_str)))
                patch = [ord(n) for n in patch_values]
                log_color(
                    f"[*] Patching section name={section.name} offset={hex(section.file_offset + addr)} orig:{patch_str} new:{patch_values}")
                binary.patch_address(section.file_offset + addr, patch)

    binary.write(input_file)

    path_strings = [
        "gum-js-loop", "gmain", "gdbus",
        "frida-gadget-tcp", "frida-gadget-unix",
        "frida-gadget-modulated", "libfrida-gadget-modulated", "frida-gadget-raw"
        "frida-gadget-universal"
        "frida-gadget",
        "frida-agent",
        "get_frida_agent_", "\'FridaAgent\'",
        "frida-helper-32", "frida-helper-64", "\"/frida-\"",
        "pool_spawner", "pool_spoiler",
    ]

    for path_string in path_strings:
        # thread_gum_js_loop
        random_name = "".join(random.sample(random_charset, len(path_string)))
        log_color(f"[*] Patch `{path_string}` to `{random_name}`")
        replace_in_binary_file(input_file, path_string, random_name)

    log_color(f"[*] Patch Finish")

    # sed

