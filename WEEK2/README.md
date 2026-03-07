# Hệ Mã Affine (Affine Cipher)

Sơ đồ hệ mã Affine được định nghĩa như sau:

$$S = (\mathcal{P}, \mathcal{C}, \mathcal{K}, \mathcal{E}, \mathcal{D})$$

---

## 1. Thành phần của hệ mã
*   **Không gian bản rõ ($\mathcal{P}$) và bản mã ($\mathcal{C}$):** $\mathcal{P}, \mathcal{C} \in \mathbb{Z}_{26}$
*   **Không gian khóa ($\mathcal{K}$):** 
    $$\mathcal{K} = \{(a, b) \in \mathbb{Z}_{26} \times \mathbb{Z}_{26} \mid \gcd(a, 26) = 1\}$$

## 2. Các ánh xạ biến đổi
Các hàm mã hóa $\mathcal{E}$ và giải mã $\mathcal{D}$ được xác định bởi:
*   **Hàm mã hóa:** $\mathcal{E}_k(x) = (ax + b) \pmod{26}$
*   **Hàm giải mã:** $\mathcal{D}_k(y) = a^{-1}(y - b) \pmod{26}$

> **Lưu ý:** Điều kiện $\gcd(a, 26) = 1$ là bắt buộc để đảm bảo luôn tồn tại phần tử nghịch đảo của $a$ (ký hiệu là $a^{-1}$) trong tập $\mathbb{Z}_{26}$, giúp việc giải mã thực hiện được.

---

## 3. Tập các giá trị của $a$ và nghịch đảo tương ứng
*   **$\phi(26)$** (Tập các số nguyên tố cùng nhau với 26):

    $$\phi(26) = \{1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25\}$$
*   **$\phi^{-1}(26)$** (Tập các phần tử nghịch đảo tương ứng trong $\mathbb{Z}_{26}$):

    $$\phi^{-1}(26) = \{1, 9, 21, 15, 3, 19, 7, 23, 11, 5, 17, 25\}$$

#### Bảng tra cứu nhanh cặp $(a, a^{-1})$:


| $a$ | 1 | 3 | 5 | 7 | 9 | 11 | 15 | 17 | 19 | 21 | 23 | 25 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **$a^{-1}$** | **1** | **9** | **21** | **15** | **3** | **19** | **7** | **23** | **11** | **5** | **17** | **25** |

---

## 4. Ưu và nhược điểm của mã Affine
### 4.1. Ưu điểm
Dù là một mật mã cổ điển, Affine vẫn có những giá trị riêng:
- Tính đơn giản và Hiệu suất cao:
    - Thuật toán chỉ dựa trên các phép tính số học cơ bản (nhân, cộng, modulo).
    - Tốc độ xử lý cực nhanh, tốn rất ít tài nguyên phần cứng, có thể triển khai trên cả những vi mạch đơn giản nhất.
- Không gian khóa lớn hơn mã Caesar:
    - Với mã Caesar, bạn chỉ có $m-1$ khả năng (ví dụ 25 khóa).
    - Với Affine, số lượng khóa là $\phi(m) \times m$. Đối với bảng chữ cái tiếng Anh, nó là $12 \times 26 = 312$ khóa. Dù vẫn nhỏ, nhưng nó đã phức tạp hơn Caesar một bậc.
### 4.2. Nhược điểm
- Lỗ hổng Phân tích Tần suất (Frequency Analysis):
    - Đây là điểm yếu chết người nhất. Vì Affine là mật mã thay thế đơn bảng (monoalphabetic), một ký tự $x$ luôn được ánh xạ cố định thành ký tự $y$.
    - Nếu kẻ tấn công biết văn bản gốc là tiếng Việt, họ chỉ cần tìm ký tự xuất hiện nhiều nhất trong bản mã và đoán đó là chữ "a", "e" hoặc "n". Chỉ cần đoán đúng 2 ký tự phổ biến, toàn bộ khóa sẽ bị lộ.
- Tấn công bản rõ đã biết (Known Plaintext Attack):
    - Nếu kẻ tấn công biết được 2 ký tự gốc và 2 ký tự mã hóa tương ứng, họ có thể thiết lập hệ phương trình:
    
    $$  \begin{cases} 
  y_1 = (a \cdot x_1 + b) \pmod m \\ 
  y_2 = (a \cdot x_2 + b) \pmod m 
  \end{cases}$$
    - Giải hệ này cực kỳ đơn giản để tìm ra cặp $(a, b)$.
- Không gian khóa quá nhỏ đối với máy tính:
    - Một máy tính hiện đại có thể thực hiện thử sai (Brute-force) toàn bộ không gian này trong vài phút hoặc vài giờ.
- Ràng buộc về khóa $a$:
    - Không phải số nào cũng làm khóa $a$ được. Việc bắt buộc $gcd(a, m) = 1$ làm hạn chế sự lựa chọn và khiến việc tạo khóa ngẫu nhiên trở nên phức tạp hơn một chút so với các loại mật mã khác.

---

## 5. Cách tính nghịch đảo modulo a
### 5.1. Trường hợp số nhỏ
Phương pháp này dựa trên việc tìm một bội số của $m$ cộng thêm 1 sao cho nó chia hết cho $a$.
#### Công thức thực hiện
$$a^{-1} = \frac{k \cdot m + 1}{a}$$
*(Với $k$ là các số nguyên $1, 2, 3...$ sao cho kết quả là số nguyên)*

#### Các bước thực hiện:
1. Lấy $m$ (thường là 26) nhân lần lượt với $k = 1, 2, 3...$
2. Cộng thêm 1 vào kết quả đó.
3. Chia thử cho $a$. Nếu chia hết, đó chính là kết quả cần tìm.

#### Ví dụ: Tìm $7^{-1} \pmod{26}$
- Với $k=1: (26 \times 1 + 1) = 27$ (không chia hết cho 7)
- Với $k=2: (26 \times 2 + 1) = 53$ (không chia hết cho 7)
- Với $k=3: (26 \times 3 + 1) = 79$ (không chia hết cho 7)
- Với $k=4: (26 \times 4 + 1) = 105$. Ta thấy $105 / 7 = 15$.
- **Kết quả:** $7^{-1} \equiv 15 \pmod{26}$.

### 5.2. Trường hợp số lớn
Đây là phương pháp chuẩn xác nhất, áp dụng được cho mọi số lớn.

#### Bước 1: Thuật toán Euclid xuôi (Chia lấy dư)
Liên tục chia số lớn cho số nhỏ cho đến khi số dư bằng 1.

**Ví dụ: Tìm $11^{-1} \pmod{26}$**
1. $26 = 2 \times 11 + 4$  (1)
2. $11 = 2 \times 4 + 3$   (2)
3. $4 = 1 \times 3 + 1$    (3)

#### Bước 2: Thuật toán Euclid ngược (Thế ngược)
Biến đổi số dư 1 về dạng tổ hợp của $a$ và $m$.

- Từ (3): $1 = 4 - 1 \times 3$
- Thế (2) vào: $1 = 4 - 1 \times (11 - 2 \times 4)$
  $\Rightarrow 1 = 3 \times 4 - 1 \times 11$
- Thế (1) vào: $1 = 3 \times (26 - 2 \times 11) - 1 \times 11$
  $\Rightarrow 1 = 3 \times 26 - 6 \times 11 - 1 \times 11$
  $\Rightarrow 1 = 3 \times 26 - 7 \times 11$

#### Bước 3: Kết luận
Hệ số đứng trước $a$ (tức là 11) chính là nghịch đảo.
- Ở đây hệ số là $-7$.
- Chuyển số âm sang dương: $-7 + 26 = 19$.
- **Kết quả:** $11^{-1} \equiv 19 \pmod{26}$.
