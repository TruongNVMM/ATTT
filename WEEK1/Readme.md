# Thuật toán Playfair
#### Copy từ slide bài giảng của giảng viên :)) 
***1. Mã Playfair***
- Thuật toán Playfair dựa trên ma trận ký tự 5 × 5 cấu trúc như là một từ
khoá. Ví dụ (solved by Lord Peter Wimsey in Dorothy Sayers’s Have His
Carcase ). Từ khoá là MONARCHY

![w1](Img\w1.png)

- Ma trận được thiết lập bằng cách điền các ký tự của từ khoá (trừ những
chữ cái trùng lặp) từ trái sang phải từ trên xuống dưới, sau đó điền vào
phần còn lại của ma trận với các chữ cái còn lại theo thứ tự bảng chữ cái.
Các chữ cái I và J được tính là một chữ cái. Bản rõ được mã hóa hai chữ
cái cùng một lúc, theo các quy tắc sau:

- Mã hóa 2 chữ cái một lúc:
    * Nếu 2 chữ giống nhau, tách ra bởi 1 chữ điền thêm
thường là X hoặc Q. Ví dụ: EE sẽ dược thay bởi EX
    * Nếu 2 chữ nằm cùng hàng, thay bởi các chữ bên
phải. Ví dụ: EF sẽ thay bằng FG
    * Nếu 2 chữ nằm cùng cột, thay bởi các chữ bên dưới.
Ví dụ: OF thay bằng HP
    * Các trường hợp khác, mỗi chữ cái được thay bởi chữ
cái khác cùng hàng, trên cột chữ cái cùng cặp. Ví dụ:
ET sẽ thay bằng KL
- Các chữ cái trong bản rõ lặp lại trong cùng một cặp được
phân tách bằng điền một chữ cái khác, như là x cho balloon sẽ
là ba lx lo on.
- Hai ký tự bản rõ nằm trong cùng một hàng của ma trận được
thay thế bằng chữ cái ở bên phải, với phần tử đầu tiên của
hàng được khoanh sau phần tử cuối cùng. Ví dụ, ar được mã
hóa là RM.
- Hai ký tự bản rõ nằm trong cùng một cột được thay thế bằng
chữ cái bên dưới, với phần tử trên cùng của cột khoanh theo
sau phần tử cuối cùng. Ví dụ: mu được mã hóa là CM.
- Mỗi cặp bản rõ được thay thế bởi ký tự nằm trên hàng và cột
của một ký tự khác, ví dụ hs thành BP và ea thành IM (or JM,
as the encipherer wishes).

***2. Nhược điểm của thuật toán***

- Dù từng được Đế quốc Anh sử dụng trong Thế chiến thứ I và thứ II nhờ tính nhanh gọn khi mã hóa bằng tay, Playfair ngày nay hoàn toàn lỗi thời và thiếu an toàn vì những lý do sau:

    * Không gian khóa quá nhỏ: Chỉ có $25!$ (khoảng $1.55 \times 10^{25}$) cách sắp xếp ma trận, nhưng do tính chất đối xứng, số lượng khóa thực tế hữu ích ít hơn nhiều. Máy tính hiện đại có thể phá khóa (brute-force) trong thời gian rất ngắn.
    * Lỗ hổng phân tích tần suất cặp (Digram Frequency): Ngôn ngữ tự nhiên có những cặp chữ cái xuất hiện cực kỳ thường xuyên (như TH, ER, ON trong tiếng Anh). Do Playfair chỉ là phép thay thế $1-1$ trên tập hợp 600 cặp chữ cái có thể có, kẻ tấn công có thể sử dụng phân tích tần suất cặp kết hợp với phương pháp leo đồi (Hill Climbing) để khôi phục ma trận khóa.
    * Tính chất cấu trúc: Ký tự mã hóa và ký tự gốc không bao giờ là cùng một chữ cái. Đồng thời, nếu cặp AB mã hóa thành CD, thì đảo ngược BA chắc chắn sẽ mã hóa thành DC. Lỗ hổng cấu trúc này làm giảm đáng kể tính "hỗn mang" (confusion) của bản mã.

***3. Cách chạy chương trình***

- Dùng lệnh `python -m WEEK1.PlayFair` trong terminal để chạy file code 
