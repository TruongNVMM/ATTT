# -*- coding: utf-8 -*-
"""
benchmark_dsa.py
================
Benchmark và kiểm tra tính đúng đắn của thuật toán DSA
dựa trên bộ test vector NIST FIPS 186-3 trong thư mục test_vector/DSA.

Test vector được sử dụng:
  - SigGen.rsp  : Kiểm tra chữ ký có khớp với R, S đã biết (dùng k cố định từ SigGen.txt)
                  Và xác minh chữ ký (R, S) đó.
  - SigVer.rsp  : Kiểm tra xác minh chữ ký – kết quả phải đúng (P/F).

Chạy từ thư mục gốc của dự án:
    python test_vector/benchmark_dsa.py
"""

import os
import sys
import time
import hashlib
import re
import io

# Fix encoding cho Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from pathlib import Path

# ── Adjust Python path để import được src package ─────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent   # Digital_Signature/
sys.path.insert(0, str(ROOT_DIR))

try:
    from src.asymmetric.DSA.DSA import DSA
except ImportError as e:
    print(f"[ERROR] Không thể import DSA: {e}")
    print("Đảm bảo chạy script từ thư mục gốc Digital_Signature/")
    sys.exit(1)

# ── Đường dẫn tới các file test vector ──────────────────────────────────────
TV_DIR = Path(__file__).parent / "DSA"
SIGGEN_RSP = TV_DIR / "SigGen.rsp"
SIGVER_RSP = TV_DIR / "SigVer.rsp"

# ── Hàm chọn hàm hash theo tên ──────────────────────────────────────────────
def make_hash_fn(hash_name: str):
    """
        Trả về hàm hash(message_bytes) -> int dựa trên tên hash.
    """
    name = hash_name.upper().replace("-", "")
    algo_map = {
        "SHA1":   "sha1",
        "SHA224": "sha224",
        "SHA256": "sha256",
        "SHA384": "sha384",
        "SHA512": "sha512",
    }
    algo = algo_map.get(name, "sha256")
    def _hash(msg_bytes: bytes, q_bits: int) -> int:
        h = hashlib.new(algo, msg_bytes).digest()
        z = int.from_bytes(h, "big")
        # Lấy leftmost min(|H|, N) bits
        h_bits = len(h) * 8
        if h_bits > q_bits:
            z >>= (h_bits - q_bits)
        return z
    return _hash

# ── Parser cho file .rsp của NIST ───────────────────────────────────────────
def parse_rsp(filepath: Path):
    """
        Đọc file .rsp NIST và trả về list các nhóm record.
        Mỗi record là dict với các trường tương ứng.
    """
    records = []
    current_header = {}   # P, Q, G của nhóm hiện tại
    current_hash = "SHA1"
    current_L = 1024
    current_N = 160
    current_record = None

    with open(filepath, encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Dòng header [mod = L=..., N=..., SHA-...]
            if line.startswith("["):
                inner = line.strip("[]")
                # parse L, N
                m = re.search(r"L=(\d+)", inner)
                if m:
                    current_L = int(m.group(1))
                m = re.search(r"N=(\d+)", inner)
                if m:
                    current_N = int(m.group(1))
                # parse hash
                m = re.search(r"SHA-?(\d+)", inner)
                if m:
                    current_hash = "SHA" + m.group(1)
                # Reset P,Q,G cho nhóm mới
                current_header = {}
                continue

            # Key=Value
            if "=" in line:
                key, _, val = line.partition("=")
                key = key.strip().upper()
                val = val.strip()

                if key == "P":
                    current_header["P"] = int(val, 16)
                elif key == "Q":
                    current_header["Q"] = int(val, 16)
                elif key == "G":
                    current_header["G"] = int(val, 16)
                elif key == "MSG":
                    # Bắt đầu record mới
                    current_record = {
                        "P": current_header.get("P"),
                        "Q": current_header.get("Q"),
                        "G": current_header.get("G"),
                        "L": current_L,
                        "N": current_N,
                        "hash": current_hash,
                        "Msg": bytes.fromhex(val),
                    }
                elif key == "Y":
                    if current_record:
                        current_record["Y"] = int(val, 16)
                elif key == "X":
                    if current_record:
                        current_record["X"] = int(val, 16)
                elif key == "R":
                    if current_record:
                        current_record["R"] = int(val, 16)
                elif key == "S":
                    if current_record:
                        current_record["S"] = int(val, 16)
                elif key == "RESULT":
                    if current_record:
                        current_record["Result"] = val.strip().upper().startswith("P")
                        records.append(current_record)
                        current_record = None
                else:
                    # Các trường khác (như trong SigGen không có Result)
                    pass

    # SigGen không có "Result" → khi gặp record hoàn chỉnh (có R và S) thì thêm
    # Xử lý record cuối nếu còn
    # Thực ra SigGen records kết thúc bằng "S" → cần cách khác
    return records


def parse_rsp_siggen(filepath: Path):
    """
        Parser riêng cho SigGen.rsp (không có trường Result).
    """
    records = []
    current_header = {}
    current_hash = "SHA1"
    current_L = 1024
    current_N = 160
    current_record = None

    with open(filepath, encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                if current_record and "R" in current_record and "S" in current_record:
                    # Hoàn thành record trước đó
                    records.append(current_record)
                    current_record = None
                continue

            if line.startswith("["):
                if current_record and "R" in current_record and "S" in current_record:
                    records.append(current_record)
                    current_record = None
                inner = line.strip("[]")
                m = re.search(r"L=(\d+)", inner)
                if m: current_L = int(m.group(1))
                m = re.search(r"N=(\d+)", inner)
                if m: current_N = int(m.group(1))
                m = re.search(r"SHA-?(\d+)", inner)
                if m: current_hash = "SHA" + m.group(1)
                current_header = {}
                continue

            if "=" in line:
                key, _, val = line.partition("=")
                key = key.strip().upper()
                val = val.strip()

                if key == "P":
                    current_header["P"] = int(val, 16)
                elif key == "Q":
                    current_header["Q"] = int(val, 16)
                elif key == "G":
                    current_header["G"] = int(val, 16)
                elif key == "MSG":
                    if current_record and "R" in current_record and "S" in current_record:
                        records.append(current_record)
                    current_record = {
                        "P": current_header.get("P"),
                        "Q": current_header.get("Q"),
                        "G": current_header.get("G"),
                        "L": current_L,
                        "N": current_N,
                        "hash": current_hash,
                        "Msg": bytes.fromhex(val),
                    }
                elif key == "Y":
                    if current_record: current_record["Y"] = int(val, 16)
                elif key == "X":
                    if current_record: current_record["X"] = int(val, 16)
                elif key == "R":
                    if current_record: current_record["R"] = int(val, 16)
                elif key == "S":
                    if current_record: current_record["S"] = int(val, 16)

    if current_record and "R" in current_record and "S" in current_record:
        records.append(current_record)

    return records


# Xác minh DSA (dùng thư viện hashlib, bỏ qua giới hạn của DSA.py)
def dsa_verify_external(P, Q, G, Y, msg_bytes, R, S, hash_fn):
    """
        Xác minh chữ ký DSA độc lập, sử dụng hashlib.
        Trả về True nếu chữ ký hợp lệ.
    """
    if not (0 < R < Q and 0 < S < Q):
        return False
    z = hash_fn(msg_bytes, Q.bit_length())
    try:
        w = pow(S, -1, Q)          # Python 3.8+
    except Exception:
        return False
    u1 = (z * w) % Q
    u2 = (R * w) % Q
    v  = (pow(G, u1, P) * pow(Y, u2, P)) % P % Q
    return v == R


# DSA sign với k cố định (để kiểm tra vector)
def dsa_sign_with_k(P, Q, G, X, msg_bytes, k, hash_fn):
    """
        Ký DSA với k cố định (dùng để xác nhận test vector).
    """
    z = hash_fn(msg_bytes, Q.bit_length())
    r = pow(G, k, P) % Q
    if r == 0:
        return None, None
    try:
        k_inv = pow(k, -1, Q)
    except Exception:
        return None, None
    s = (k_inv * (z + X * r)) % Q
    if s == 0:
        return None, None
    return r, s


# ── Benchmark SigVer ──────────────────────────────────────────────────────────
def benchmark_sigver(records, max_records=200):
    """
        Chạy benchmark xác minh chữ ký (SigVer).
        So sánh kết quả với trường Result trong file.
    """
    print("  BENCHMARK: SigVer (Signature Verification)")

    total = min(len(records), max_records)
    passed = 0
    failed = 0
    wrong  = 0   # Kết quả xác minh không khớp với expected

    start_all = time.perf_counter()

    for i, rec in enumerate(records[:max_records]):
        P, Q, G = rec["P"], rec["Q"], rec["G"]
        Y   = rec.get("Y")
        R   = rec.get("R")
        S   = rec.get("S")
        msg = rec.get("Msg", b"")
        expected = rec.get("Result", True)
        hash_fn  = make_hash_fn(rec.get("hash", "SHA256"))

        if not all([P, Q, G, Y, R, S]):
            continue

        t0 = time.perf_counter()
        result = dsa_verify_external(P, Q, G, Y, msg, R, S, hash_fn)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        if result == expected:
            passed += 1
            status = "PASS"
        else:
            wrong += 1
            status = f"WRONG (got={'P' if result else 'F'}, exp={'P' if expected else 'F'})"

        # In chi tiết cho 10 record đầu
        if i < 10:
            print(f"  [{i+1:4d}] {rec['hash']:6s} L={rec['L']:4d}/N={rec['N']:3d}  "
                  f"{elapsed_ms:6.3f} ms  {status}")

    elapsed_total = time.perf_counter() - start_all

    print(f"\n  Tổng số: {total}  |  PASS: {passed}  |  WRONG: {wrong}")
    print(f"  Thời gian tổng: {elapsed_total*1000:.1f} ms  "
          f"| TB mỗi lần xác minh: {elapsed_total/total*1000:.3f} ms")
    print(f"  Tốc độ: {total/elapsed_total:.1f} verifications/giây")
    return passed, wrong, total


# Benchmark SigGen (xác minh chữ ký đã biết R,S) 
def benchmark_siggen(records, max_records=100):
    """
        Benchmark sinh và xác minh chữ ký qua SigGen.rsp.
        Chỉ xác minh (verify) chữ ký (R,S) với public key Y.
        Không thể tái tạo đúng (R,S) vì k không có trong SigGen.rsp.
    """
    print("  BENCHMARK: SigGen Vector Verification (Verify known signatures)")

    total = min(len(records), max_records)
    passed = 0
    wrong  = 0

    start_all = time.perf_counter()

    for i, rec in enumerate(records[:max_records]):
        P, Q, G = rec["P"], rec["Q"], rec["G"]
        Y   = rec.get("Y")
        R   = rec.get("R")
        S   = rec.get("S")
        msg = rec.get("Msg", b"")
        hash_fn = make_hash_fn(rec.get("hash", "SHA256"))

        if not all([P, Q, G, Y, R, S]):
            continue

        t0 = time.perf_counter()
        result = dsa_verify_external(P, Q, G, Y, msg, R, S, hash_fn)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        if result:
            passed += 1
            status = "PASS"
        else:
            wrong += 1
            status = "WRONG (should be valid)"

        if i < 10:
            print(f"  [{i+1:4d}] {rec['hash']:6s} L={rec['L']:4d}/N={rec['N']:3d}  "
                  f"{elapsed_ms:6.3f} ms  {status}")

    elapsed_total = time.perf_counter() - start_all

    print(f"\n  Tổng số: {total}  |  Hợp lệ: {passed}  |  Không hợp lệ: {wrong}")
    print(f"  Thời gian tổng: {elapsed_total*1000:.1f} ms  "
          f"| TB mỗi lần xác minh: {elapsed_total/total*1000:.3f} ms")
    print(f"  Tốc độ: {total/elapsed_total:.1f} verifications/giây")
    return passed, wrong, total


# Benchmark tích hợp: Sign + Verify dùng DSA.py
def benchmark_sign_verify_dsa_class(records, max_records=50):
    """
        Dùng lớp DSA trong src để Sign và Verify.
        Kiểm tra rằng chữ ký được tạo ra có thể xác minh thành công.
        Chỉ dùng tham số từ vector (L=1024, N=160, SHA-256) vì DSA.py dùng SHA-256.
    """
    print("  BENCHMARK: DSA Class – Sign + Verify (SHA-256 only)")

    # Lọc lấy các record có X (private key) để có thể ký
    # Ưu tiên SHA-256 (tương thích DSA.py), nhưng test tất cả nếu cần
    sha256_records = [r for r in records if r.get("hash") == "SHA256"
                      and r.get("P") and r.get("Q") and r.get("G")
                      and r.get("X") and r.get("Y")]
    # Nếu không có SHA-256, fallback sang tất cả hash có X
    if not sha256_records:
        sha256_records = [r for r in records
                          if r.get("P") and r.get("Q") and r.get("G")
                          and r.get("X") and r.get("Y")]

    total = min(len(sha256_records), max_records)
    if total == 0:
        print("  Khong co record SHA-256 phu hop.")
        return 0, 0, 0

    passed = 0
    failed = 0
    sign_times  = []
    verify_times = []

    for i, rec in enumerate(sha256_records[:max_records]):
        P, Q, G = rec["P"], rec["Q"], rec["G"]
        X   = rec.get("X")
        Y   = rec.get("Y")
        msg = rec.get("Msg", b"")

        try:
            dsa = DSA(p=P, q=Q, g=G)
            dsa.set_private_key(X)

            # Sign
            t0 = time.perf_counter()
            R_new, S_new = dsa.sign(msg)
            sign_times.append(time.perf_counter() - t0)

            # Verify
            t0 = time.perf_counter()
            ok = dsa.verify(msg, (R_new, S_new), public_key=Y)
            verify_times.append(time.perf_counter() - t0)

            if ok:
                passed += 1
                status = "PASS"
            else:
                failed += 1
                status = "FAIL (sign then verify returned False)"
        except Exception as exc:
            failed += 1
            status = f"ERROR: {exc}"
            sign_times.append(0)
            verify_times.append(0)

        if i < 10:
            s_ms = sign_times[-1] * 1000
            v_ms = verify_times[-1] * 1000
            print(f"  [{i+1:4d}] L={rec['L']:4d}/N={rec['N']:3d}  "
                  f"Sign={s_ms:7.3f}ms  Verify={v_ms:7.3f}ms  {status}")

    avg_sign   = sum(sign_times) / len(sign_times) * 1000 if sign_times else 0
    avg_verify = sum(verify_times) / len(verify_times) * 1000 if verify_times else 0
    total_time = sum(sign_times) + sum(verify_times)

    print(f"\n  Tổng số: {total}  |  PASS: {passed}  |  FAIL: {failed}")
    print(f"  Trung bình Sign  : {avg_sign:.3f} ms")
    print(f"  Trung bình Verify: {avg_verify:.3f} ms")
    print(f"  Thời gian tổng (sign+verify): {total_time*1000:.1f} ms")
    print(f"  Tốc độ Sign  : {1000/avg_sign:.1f} ops/s" if avg_sign else "  N/A")
    print(f"  Tốc độ Verify: {1000/avg_verify:.1f} ops/s" if avg_verify else "  N/A")
    return passed, failed, total


# ── Phân tích theo tham số ───────────────────────────────────────────────────
def analyze_by_params(records, label="SigVer"):
    """
        In thống kê thời gian xác minh theo (L, N, Hash).
    """
    print(f"  PHÂN TÍCH HIỆU SUẤT THEO THAM SỐ ({label})")

    print(f"  {'L':>6}  {'N':>4}  {'Hash':>8}  {'Số luợng':>8}  {'TB (ms)':>9}  {'Min (ms)':>9}  {'Max (ms)':>9}")
    print(f"  {'-'*6}  {'-'*4}  {'-'*8}  {'-'*8}  {'-'*9}  {'-'*9}  {'-'*9}")

    # Nhóm theo (L, N, hash)
    from collections import defaultdict
    groups = defaultdict(list)

    for rec in records:
        P, Q, G = rec.get("P"), rec.get("Q"), rec.get("G")
        Y = rec.get("Y"); R = rec.get("R"); S = rec.get("S")
        msg = rec.get("Msg", b"")
        if not all([P, Q, G, Y, R, S]):
            continue
        hash_fn = make_hash_fn(rec.get("hash", "SHA256"))
        key = (rec["L"], rec["N"], rec.get("hash", "SHA256"))
        t0 = time.perf_counter()
        dsa_verify_external(P, Q, G, Y, msg, R, S, hash_fn)
        groups[key].append((time.perf_counter() - t0) * 1000)

    for (L, N, h), times in sorted(groups.items()):
        avg = sum(times) / len(times)
        print(f"  {L:>6}  {N:>4}  {h:>8}  {len(times):>8}  {avg:>9.3f}  "
              f"{min(times):>9.3f}  {max(times):>9.3f}")


#  Main
def main():
    # -- Doc file SigGen.rsp
    print(f"\n[*] Doc SigGen.rsp ...", end=" ")
    if not SIGGEN_RSP.exists():
        print(f"KHONG TIM THAY: {SIGGEN_RSP}")
        sys.exit(1)
    siggen_records = parse_rsp_siggen(SIGGEN_RSP)
    print(f"{len(siggen_records)} records")

    # -- Doc file SigVer.rsp
    print(f"[*] Doc SigVer.rsp  ...", end=" ")
    if not SIGVER_RSP.exists():
        print(f"KHONG TIM THAY: {SIGVER_RSP}")
        sys.exit(1)
    sigver_records = parse_rsp(SIGVER_RSP)
    print(f"{len(sigver_records)} records")

    ''' 
        1. SigGen: xac minh cac vector chu ky da tao san
    '''
    sg_pass, sg_wrong, sg_total = benchmark_siggen(siggen_records, max_records=200)

    ''' 
        2. SigVer: kiem tra xac minh voi ket qua P/F
    '''
    sv_pass, sv_wrong, sv_total = benchmark_sigver(sigver_records, max_records=300)

    ''' 
        3. DSA class: Sign + Verify end-to-end
        Dung tham so tu SigVer (co truong X) + DSA.py (SHA-256)
    '''
    # SigVer record co X; truyen vao de co the sign
    dc_pass, dc_fail, dc_total = benchmark_sign_verify_dsa_class(
        sigver_records + siggen_records, max_records=50)

    
    ''' 
        4. Phan tich theo tham so
    ''' 
    analyze_by_params(sigver_records[:500], label="SigVer")

    print("  TOM TAT KET QUA BENCHMARK")

    print(f"  SigGen Verify : {sg_pass}/{sg_total} PASS  ({sg_wrong} WRONG)")
    print(f"  SigVer P/F    : {sv_pass}/{sv_total} PASS  ({sv_wrong} WRONG)")
    print(f"  DSA Class     : {dc_pass}/{dc_total} PASS  ({dc_fail} FAIL)")

    total_ok  = sg_pass + sv_pass + dc_pass
    total_all = sg_total + sv_total + dc_total
    acc = total_ok / total_all * 100 if total_all else 0
    print(f"\nTổng độ chính xác: {total_ok}/{total_all} = {acc:.1f}%")

    if sv_wrong == 0 and sg_wrong == 0:
        print("\nTất cả test vector đều PASS – thuật toán DSA hoạt động đúng!")
    else:
        print(f"\nCó {sv_wrong + sg_wrong} test vector WRONG – cần kiểm tra lại!")
    print()


if __name__ == "__main__":
    main()
