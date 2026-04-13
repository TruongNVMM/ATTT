# -*- coding: utf-8 -*-
"""
benchmark_rsa.py
================
Benchmark và kiểm tra tính đúng đắn của thuật toán RSA.
Kịch bản test sử dụng các test vector NIST FIPS 186-2/3 (SigGenRSA.rsp, SigVerRSA.rsp).

Do lớp RSA.py hiện tại được thiết kế mã hóa/ký từng ký tự (Textbook RSA minh họa),
nó không tương thích trực tiếp với chuẩn Padding nguyên khối (như PKCS#1 v1.5 hay X9.31) 
của NIST (trong đó S là một số nguyên duy nhất S = EM^d mod n). 

Vì vậy, script này thực hiện:
1. Benchmarking Tốc độ Toán học Lõi của RSA (Core Math Benchmark) dựa trên file SigVerRSA.rsp 
   bằng cách tính trực tiếp S^e mod n (quá trình xác minh).
2. Benchmarking hiệu suất của lớp RSA.py hiện tại (Mã hóa từng ký tự) dựa trên nội dung Msg.
"""

import os
import sys
import time
import re
import io
from pathlib import Path

# Fix encoding cho Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Adjust Python path để import được src package 
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

try:
    from src.asymmetric.RSA.RSA import RSA
except ImportError as e:
    print(f"[ERROR] Không thể import RSA: {e}")
    print("Đảm bảo chạy script từ thư mục gốc Digital_Signature/")
    sys.exit(1)

TV_DIR = Path(__file__).parent / "RSA"
SIGVER_RSP = TV_DIR / "SigVerRSA.rsp"
SIGGEN_RSP = TV_DIR / "SigGenRSA.rsp"

def parse_rsa_rsp(filepath: Path):
    """
        Parse file NIST RSA .rsp (có hỗ trợ SigVerRSA.rsp và SigGenRSA.rsp).
        Trả về danh sách các record.
    """
    records = []
    current_mod = 1024
    
    # State toàn cục theo file
    global_n = None
    
    current_record = {}

    if not filepath.exists():
        print(f"[WARN] Không tìm thấy {filepath.name}")
        return records

    with open(filepath, encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Header mod, ví dụ: [mod = 1024]
            if line.startswith("[") and "mod" in line.lower():
                m = re.search(r"mod\s*=\s*(\d+)", line, re.IGNORECASE)
                if m:
                    current_mod = int(m.group(1))
                continue

            if "=" in line:
                key, _, val = line.partition("=")
                key = key.strip().upper()
                val = val.strip()

                # Đôi khi header n chung cho toàn bộ
                if key == "N":
                    global_n = int(val, 16)
                    current_record["N"] = global_n
                elif key == "E":
                    current_record["E"] = int(val, 16)
                elif key == "D":
                    current_record["D"] = int(val, 16)
                elif key == "SHAALG":
                    current_record["SHA"] = val
                elif key == "MSG":
                    current_record["MSG_HEX"] = val
                elif key == "S":
                    current_record["S"] = int(val, 16)
                    # Nếu là SigGen (không có Result), coi như hoàn thành record tại S
                    if "SigGen" in filepath.name:
                        rec = current_record.copy()
                        rec["MOD"] = current_mod
                        if "N" not in rec and global_n is not None:
                            rec["N"] = global_n
                        records.append(rec)
                        
                        # Reset các trường đặc thù của message
                        current_record = {k: v for k, v in current_record.items() if k in ["N", "E", "D", "SHA"]}
                elif "RESULT" in key:
                    is_pass = val.upper().startswith("P")
                    current_record["RESULT"] = is_pass
                    rec = current_record.copy()
                    rec["MOD"] = current_mod
                    if "N" not in rec and global_n is not None:
                        rec["N"] = global_n
                    records.append(rec)
                    
                    current_record = {k: v for k, v in current_record.items() if k in ["N", "E", "D", "SHA"]}

    return records

def benchmark_native_math(records):
    """
        Kiểm tra tốc độ của phương trình xác minh S^e mod n độc lập.
        Đây là cốt lõi của RSA.
    """

    print(" 1. BENCHMARK TOÁN HỌC LÕI RSA (Native Mod Exponentiation)")

    if not records:
        print("[!] Không có dữ liệu để test.")
        return

    # Group by Mod size
    by_mod = {}
    for r in records:
        mod = r.get("MOD", 1024)
        if mod not in by_mod:
            by_mod[mod] = []
        by_mod[mod].append(r)

    print(f"{'Modulus (bits)':<15} | {'Verifications':<15} | {'Ops/sec':<15} | {'Avg Time (ms)'}")
    print("-" * 70)

    for mod in sorted(by_mod.keys()):
        group = by_mod[mod]
        valid_records = [r for r in group if "S" in r and "E" in r and "N" in r]
        if not valid_records:
            continue
        
        total_verify = len(valid_records)
        v_start = time.perf_counter()
        
        for r in valid_records:
            # Mô phỏng quá trình xác minh lõi của RSA: Tính EM = S^e mod n
            em = pow(r["S"], r["E"], r["N"])
            
        v_end = time.perf_counter()
        v_time = v_end - v_start
        v_ops = total_verify / v_time if v_time > 0 else 0
        v_avg_ms = (v_time / total_verify) * 1000 if total_verify > 0 else 0
        
        print(f"{mod:<15} | {total_verify:<15} | {v_ops:<15.2f} | {v_avg_ms:.3f}")

def benchmark_rsa_class(records):
    """
        Benchmark lớp mô phỏng RSA trong src.asymmetric.RSA.RSA.
        Lớp này dùng mảng ký tự minh họa, nên ta chỉ test hiệu suất sign/verify chuỗi.
    """

    print(" 2. BENCHMARK TÍCH HỢP RSA CLASS (src/asymmetric/RSA/RSA.py)")
    if not records:
        print("[!] Không có dữ liệu để test.")
        return
    
    rsa_inst = RSA()
    
    # Chỉ chọn 1 record hợp lệ cho mỗi Mod Size để kiểm tra, tránh tốn quá nhiều thời gian.
    # Textbook RSA mã hóa từng byte nên với Modsize 4096 sẽ rất nặng.
    test_cases = {}
    for r in records:
        mod = r.get("MOD")
        if mod not in test_cases and "D" in r and "E" in r and "N" in r and "MSG_HEX" in r:
            test_cases[mod] = r

    if not test_cases:
        print("[!] Không tìm thấy record hỗ trợ đầy đủ khóa (D, E, N).")
        return

    print(f"{'Modulus':<10} | {'Msg Len':<8} | {'Sign Time(s)':<12} | {'Verify Time(s)':<12} | {'Result'}")

    for mod in sorted(test_cases.keys()):
        r = test_cases[mod]
        # Chuyển Hex Msg thành chuỗi ASCII thô để RSA.py có thể xử lý qua ord()
        try:
            msg_str = bytes.fromhex(r["MSG_HEX"]).decode('latin-1')
        except:
            msg_str = r["MSG_HEX"] # Dự phòng

        pub_key = (r["E"], r["N"])
        priv_key = (r["D"], r["N"])
        
        rsa_inst.set_public_key(pub_key)
        rsa_inst.set_private_key(priv_key)
        
        # Rút ngắn message nếu quá dài để tránh treo máy ứng với thuật toán loop của class
        if len(msg_str) > 100:
            msg_str = msg_str[:100]

        # 1. Sign
        s_start = time.perf_counter()
        signature = rsa_inst.sign(msg_str)
        s_end = time.perf_counter()
        sign_time = s_end - s_start
        
        # 2. Verify
        v_start = time.perf_counter()
        is_valid = rsa_inst.verify(msg_str, signature)
        v_end = time.perf_counter()
        verify_time = v_end - v_start

        res_str = "PASS" if is_valid else "FAIL"
        
        print(f"{mod:<10} | {len(msg_str):<8} | {sign_time:<12.4f} | {verify_time:<12.4f} | {res_str}")


def main():
    print("Đang đọc dữ liệu NIST Test Vectors cho RSA...")
    sigver_records = parse_rsa_rsp(SIGVER_RSP)
    siggen_records = parse_rsa_rsp(SIGGEN_RSP)
    
    all_records = sigver_records + siggen_records
    print(f"[+] Đã tải {len(sigver_records)} records từ SigVerRSA.rsp")
    print(f"[+] Đã tải {len(siggen_records)} records từ SigGenRSA.rsp")
    
    benchmark_native_math(all_records)
    
    benchmark_rsa_class(sigver_records)

if __name__ == "__main__":
    main()
