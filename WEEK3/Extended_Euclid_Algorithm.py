def poly_divmod(a, b):
    """
    Phép chia đa thức lấy nguyên và dư trong GF(2)
    Tham số: 
        - a: số chia
        - b: số bị chia
    Đầu ra: 
        - q: thương
        - r: dư
    Phương thức:
        - Sử dụng bit_length() để xác định bậc của đa thức
    """

    if b == 0:
        raise ZeroDivisionError
    q = 0
    r = a

    # Tiếp tục thực hiện phép chia cho đến khi bậc của r nhỏ hơn bậc của b
    while r >= b and r.bit_length() >= b.bit_length():
        shift = r.bit_length() - b.bit_length()   # Tính số bit cần dịch để b có cùng bậc với r
        q ^= (1 << shift)                         # Phép cộng (XOR) vào thương
        r ^= (b << shift)                         # Phép trừ (XOR) đa thức
    return q, r

def poly_mul(a, b):
    """
    Phép nhân đa thức trong GF(2)
    Tham số: 
        - a: đa thức thứ nhất
        - b: đa thức thứ hai
    Đầu ra:
        - res: kết quả của phép nhân
    Phương thức:
        - Sử dụng phép dịch bit và XOR để thực hiện phép nhân
    """

    res = 0
    while b > 0:
        if b & 1:
            res ^= a

        a <<= 1
        b >>= 1
    return res

def print_row(col1, col2, width1=50, width2=50):
    """
    Hàm in format bảng với các viền ngăn cách
    """
    lines1 = col1.split('\n')
    lines2 = col2.split('\n')
    max_lines = max(len(lines1), len(lines2))
    
    for i in range(max_lines):
        l1 = lines1[i] if i < len(lines1) else ""
        l2 = lines2[i] if i < len(lines2) else ""
        print(f"| {l1:<{width1}} | {l2:<{width2}} |")
    print("-" * (width1 + width2 + 7))


def get_name(idx):
    """
    Lấy đúng tên gọi a(x), b(x) hoặc r_i(x) giống trong bảng mẫu
    """
    if idx == -1: return "a(x)"
    if idx == 0: return "b(x)"
    return f"r_{idx}(x)"

def extended_euclidean_gf2(m, val):
    '''
    Thuật toán Euclid mở rộng để tìm nghịch đảo nhân trong trường GF(2^n)
    Tham số:    
        - m: đa thức m(x) (dạng integer)
        - val: đa thức cần tìm nghịch đảo (dạng integer)
    Đầu ra:
        - Nghịch đảo nhân của val trong GF(2^n)
    Phương thức:
        - Sử dụng bảng để hiển thị quá trình tính toán
    '''

    print("-" * 107)
    print_row("Calculate", "Calculate")
    
    r_prev2, r_prev1 = m, val
    v_prev2, v_prev1 = 1, 0
    w_prev2, w_prev1 = 0, 1
    
    # In ra 2 dòng đầu tiên
    print_row(f"r_-1(x) = a(x) = {r_prev2}", f"v_-1(x) = 1; w_-1(x) = 0")
    print_row(f"r_0(x) = b(x) = {r_prev1}", f"v_0(x) = 0; w_0(x) = 1")
    
    i = 1
    while True:
        # Tính thương và dư
        q, r = poly_divmod(r_prev2, r_prev1)
        
        # Điều kiện kết thúc: Phần dư bằng 0
        if r == 0:
            calc1 = f"r_{i}(x) = {get_name(i-2)} mod {get_name(i-1)} = 0\n" \
                    f"q_{i}(x) = quotient of {get_name(i-2)}/{get_name(i-1)} = {q}"
            calc2 = "" # Cột 2 rỗng khi kết thúc thuật toán
            print_row(calc1, calc2)
            break
            
        # Tính toán v_i và w_i (Dấu '-' trong GF(2) chính là phép XOR)
        v = v_prev2 ^ poly_mul(q, v_prev1)
        w = w_prev2 ^ poly_mul(q, w_prev1)
        
        # Format string giống với bảng
        calc1 = f"r_{i}(x) = {get_name(i-2)} mod {get_name(i-1)} = {r}\n" \
                f"q_{i}(x) = quotient of {get_name(i-2)}/{get_name(i-1)} = {q}"
                
        calc2 = f"v_{i}(x) = v_{i-2}(x) - q_{i}(x)v_{i-1}(x) = {v}\n" \
                f"w_{i}(x) = w_{i-2}(x) - q_{i}(x)w_{i-1}(x) = {w}"
        
        print_row(calc1, calc2)
        
        # Cập nhật biến cho vòng lặp tiếp theo
        r_prev2, r_prev1 = r_prev1, r
        v_prev2, v_prev1 = v_prev1, v
        w_prev2, w_prev1 = w_prev1, w
        i += 1
        
    print(f"\nNghịch đảo nhân của {val} là w_{i-1}(x) = {w_prev1}\n")
    return w_prev1

if __name__ == "__main__":
    m_poly = 1033 # Biểu diễn dạng integer của x^10 + x^3 + 1
    
    # 1. Tìm nghịch đảo của a = 523
    extended_euclidean_gf2(m_poly, 523)
    
    # 2. Tìm nghịch đảo của b = 1015
    extended_euclidean_gf2(m_poly, 1015)
