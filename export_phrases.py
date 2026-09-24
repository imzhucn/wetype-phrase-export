# -*- coding: utf-8 -*-
"""
微信输入法 (WeType) PC 版常用语全量导出工具
原理：从正在运行的输入法进程内存中反解 Flutter StandardMessageCodec 结构，免破解直接提取常用语。
"""

import ctypes
from ctypes import wintypes
import os
import sys
import re
import struct
import json
import csv
import argparse

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.restype = ctypes.c_size_t
VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.restype = wintypes.BOOL
ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

def get_wetype_pids():
    """获取所有运行中的微信输入法核心进程 PID"""
    import subprocess
    cmd = 'powershell "Get-Process wetype_update, wetype_server -ErrorAction SilentlyContinue | Select-Object Id, ProcessName"'
    try:
        out = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
    except Exception:
        out = ""
    pids = []
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0].isdigit():
            pids.append((int(parts[0]), parts[1]))
    return pids

def read_flutter_str(buf, pos):
    """
    解析 Flutter StandardMessageCodec 字符串类型 (Tag 0x07)
    长度编码规则:
      - 0..253: 单字节
      - 254: 后跟 2 字节小端无符号整数 (<H)
      - 255: 后跟 4 字节小端无符号整数 (<I)
    """
    if pos >= len(buf):
        return None, pos
    typ = buf[pos]
    if typ != 7: # Flutter String Tag
        return None, pos
    pos += 1
    if pos >= len(buf):
        return None, pos
    ln = buf[pos]
    pos += 1
    if ln == 254:
        if pos + 2 > len(buf): return None, pos
        ln = struct.unpack_from('<H', buf, pos)[0]
        pos += 2
    elif ln == 255:
        if pos + 4 > len(buf): return None, pos
        ln = struct.unpack_from('<I', buf, pos)[0]
        pos += 4
    if pos + ln > len(buf):
        return None, pos
    s = buf[pos:pos+ln].decode('utf-8', errors='ignore')
    return s, pos + ln

def extract_from_buffer(buf):
    """从内存缓冲区中提取所有匹配的 hw_id、key、text 结构"""
    items = []
    pattern = rb'\x07\x05hw_id'
    for m in re.finditer(pattern, buf):
        pos = m.start()
        hw_id_key, pos = read_flutter_str(buf, pos)
        hw_id, pos = read_flutter_str(buf, pos)
        key_key, pos = read_flutter_str(buf, pos)
        key, pos = read_flutter_str(buf, pos)
        text_key, pos = read_flutter_str(buf, pos)
        text, pos = read_flutter_str(buf, pos)
        if hw_id_key == 'hw_id' and key_key == 'key' and text_key == 'text':
            items.append({
                "hw_id": hw_id,
                "key": key,
                "text": text
            })
    return items

def export_wetype_phrases(output_dir=None):
    """主执行逻辑：扫描进程、解码数据并导出多格式文件"""
    if not output_dir:
        # 默认保存到当前脚本所在目录下的 result/
        script_dir = os.path.dirname(os.path.abspath(__file__))
        output_dir = os.path.join(script_dir, "result")

    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("微信输入法 (WeType) 常用语全量导出工具")
    print("=" * 60)

    pids = get_wetype_pids()
    if not pids:
        print("[!] 未检测到运行中的微信输入法进程 (wetype_update / wetype_server)！")
        print("    请先启动微信输入法，并确保常用语功能正常可用。")
        return False

    all_found = {}

    for pid, name in pids:
        print(f"[*] 正在扫描进程 [{name}] (PID: {pid})...")
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not hProcess:
            continue

        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        mbi_size = ctypes.sizeof(mbi)

        try:
            while VirtualQueryEx(hProcess, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size):
                base = mbi.BaseAddress
                size = mbi.RegionSize
                state = mbi.State
                protect = mbi.Protect
                address = (base or 0) + size

                if state == MEM_COMMIT and not (protect & PAGE_GUARD) and not (protect & PAGE_NOACCESS):
                    buf = ctypes.create_string_buffer(size)
                    bytesRead = ctypes.c_size_t(0)
                    if ReadProcessMemory(hProcess, ctypes.c_void_p(base), buf, size, ctypes.byref(bytesRead)):
                        raw = bytes(buf[:bytesRead.value])
                        if b'\x07\x05hw_id' in raw:
                            items = extract_from_buffer(raw)
                            for it in items:
                                all_found[it['hw_id']] = it
        finally:
            CloseHandle(hProcess)

    total_count = len(all_found)
    print(f"\n[+] 扫描完成！共提取到 {total_count} 条有效常用语条目。")
    if total_count == 0:
        print("[-] 未能在内存中提取到常用语，可能输入法尚未从云端同步或未加载常用语。")
        return False

    # 排序：按 hw_id 倒序排列（新创建的在前面）
    term_list = sorted(list(all_found.values()), key=lambda x: x['hw_id'], reverse=True)

    # 1. 导出 JSON (结构化元数据)
    json_path = os.path.join(output_dir, "微信输入法常用语_导出.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(term_list, f, ensure_ascii=False, indent=2)
    print(f"  [1] JSON 数据已保存: {json_path}")

    # 2. 导出 CSV (Excel 可视化表格)
    csv_path = os.path.join(output_dir, "微信输入法常用语_导出.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["输入码(key)", "常用语内容(text)", "条目唯一ID(hw_id)"])
        for it in term_list:
            writer.writerow([it['key'], it['text'], it['hw_id']])
    print(f"  [2] CSV 表格已保存:  {csv_path}")

    # 3. 导出通用自定义短语文本 (搜狗 / Rime / 微信输入法通用)
    txt_path = os.path.join(output_dir, "微信输入法常用语_导出_通用词库.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("# 微信输入法常用语导出文件\n")
        f.write("# 适用范围: 搜狗输入法自定义短语、Rime 用户词典、微信输入法等\n")
        f.write("# 格式: 输入码,候选位置=短语正文 (多行文本以 \\n 转义)\n\n")
        for it in term_list:
            k = it['key']
            t = it['text'].replace('\r\n', '\n').replace('\n', '\\n')
            if k:
                f.write(f"{k},1={t}\n")
            else:
                f.write(f"# [无输入码] {t}\n")
    print(f"  [3] 通用词库已保存: {txt_path}")

    print("\n--- 提取样本预览 (前 5 条) ---")
    for idx, it in enumerate(term_list[:5], 1):
        key_display = f"[{it['key']}]" if it['key'] else "[无输入码]"
        text_display = it['text'].replace('\n', ' ')
        if len(text_display) > 50:
            text_display = text_display[:50] + "..."
        print(f"  {idx}. {key_display:<10} => {text_display}")
    print("=" * 60)
    return True

def main():
    parser = argparse.ArgumentParser(description="微信输入法常用语一键导出工具")
    parser.add_argument("-o", "--output", help="指定导出目录 (默认 ./result)", default=None)
    args = parser.parse_args()
    success = export_wetype_phrases(output_dir=args.output)
    if not success:
        sys.exit(1)

if __name__ == '__main__':
    main()
