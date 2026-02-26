import re

class PlayfairCipher:
    def __init__(self, key: str):
        self.matrix = self._generate_matrix(key)

    def _generate_matrix(self, key: str) -> list:
        # Làm sạch từ khóa: viết hoa, thay J bằng I, loại bỏ ký tự không phải chữ
        key = re.sub(r'[^A-Z]', '', key.upper().replace('J', 'I'))
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        
        matrix_str = ""
        # Thêm từ khóa vào chuỗi ma trận (tránh trùng lặp)
        for char in key + alphabet:
            if char not in matrix_str:
                matrix_str += char
                
        # Cắt chuỗi thành mảng 2 chiều 5x5
        return [list(matrix_str[i:i+5]) for i in range(0, 25, 5)]

    def _prepare_text(self, text: str) -> str:
        # Làm sạch văn bản gốc
        text = re.sub(r'[^A-Z]', '', text.upper().replace('J', 'I'))
        prepared = ""
        
        i = 0
        while i < len(text):
            char1 = text[i]
            if i + 1 < len(text):
                char2 = text[i+1]
                if char1 == char2: # Xử lý trùng chữ cái trong cặp
                    prepared += char1 + 'X'
                    i += 1
                else:
                    prepared += char1 + char2
                    i += 2
            else: # Xử lý ký tự bị lẻ ở cuối
                prepared += char1 + 'X'
                i += 1
        return prepared

    def _find_position(self, char: str) -> tuple:
        # Tìm tọa độ (hàng, cột) của một ký tự trong ma trận
        for row in range(5):
            for col in range(5):
                if self.matrix[row][col] == char:
                    return row, col
        raise ValueError(f"Ký tự {char} không tồn tại trong ma trận.")

    def process(self, text: str, mode: str = 'encrypt') -> str:
        if mode == 'encrypt':
            text = self._prepare_text(text)
            shift = 1 # Dịch tiến (phải/xuống)
        elif mode == 'decrypt':
            # Bản mã giả định đã là các cặp hợp lệ
            shift = -1 # Dịch lùi (trái/lên)
        else:
            raise ValueError("Mode chỉ nhận 'encrypt' hoặc 'decrypt'")

        result = ""
        for i in range(0, len(text), 2):
            r1, c1 = self._find_position(text[i])
            r2, c2 = self._find_position(text[i+1])

            # Áp dụng 3 quy tắc
            if r1 == r2: # Cùng hàng
                result += self.matrix[r1][(c1 + shift) % 5] + self.matrix[r2][(c2 + shift) % 5]
            elif c1 == c2: # Cùng cột
                result += self.matrix[(r1 + shift) % 5][c1] + self.matrix[(r2 + shift) % 5][c2]
            else: # Hình chữ nhật (Khác hàng, khác cột)
                result += self.matrix[r1][c2] + self.matrix[r2][c1]

        return result
