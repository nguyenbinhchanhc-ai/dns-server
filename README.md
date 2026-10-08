# Antigravity Hyper-Speed DNS over HTTPS (DoH) Proxy

Máy chủ proxy DNS-over-HTTPS (DoH) hiệu năng cao, tối ưu hóa thuật toán chia tải thích ứng (Adaptive P2C & Hedged Racing), hỗ trợ RAM Caching + SWR (Stale-While-Revalidate), sẵn sàng triển khai trên **Vercel**, **Render**, hoặc **Node.js Server**.

---

## 🚀 Hướng Dẫn Deploy Lên Vercel (Trong 1 Phút)

### Cách 1: Deploy qua Giao diện Web Vercel (Khuyên dùng)
1. Đẩy (push) mã nguồn này lên repository GitHub của bạn (`nguyenbinhchanhc-ai/dns-server`).
2. Truy cập [vercel.com](https://vercel.com) và đăng nhập bằng GitHub.
3. Bấm **"Add New..."** ➔ **"Project"**.
4. Chọn repository `dns-server` và bấm **"Import"**.
5. Giữ nguyên toàn bộ cấu hình mặc định (Framework Preset: Other / Build Command: để trống) vì dự án đã có sẵn file `vercel.json` và `api/index.js`.
6. Bấm **"Deploy"**.

Sau khi Vercel hoàn tất build (~20 giây), bạn sẽ nhận được tên miền công khai mở hoàn toàn, ví dụ:
```
https://ten-du-an-cua-ban.vercel.app
```

---

## 📱 Cài Đặt DoH Lên iPhone / iPad (iOS)

Khi đã có đường dẫn Vercel của bạn, URL DoH sẽ là:
```
https://ten-du-an-cua-ban.vercel.app/dns-query
```

### Cách cài đặt vào iPhone:
1. Mở ứng dụng quản lý DNS trên iOS (ví dụ: **DNSCloak**, **AdGuard**, **DNSecure** hoặc profile iOS `.mobileconfig`).
2. Trong mục **Server URL** (hoặc DoH URL), nhập:
   ```
   https://ten-du-an-cua-ban.vercel.app/dns-query
   ```
3. Bật kết nối DNS. 
4. **Xong!** Toàn bộ truy vấn mạng của điện thoại sẽ được phân giải qua Vercel Edge CDN và cụm DNS tối ưu mà không sợ bị chặn hay mất kết nối.

---

## ⚡ Các Điểm Nổi Bật Được Tối Ưu Cho Vercel

1. **Vercel Edge Global Caching**:
   - Tích hợp header `Cache-Control: public, s-maxage=300, stale-while-revalidate=86400`.
   - Các tên miền phổ biến được Vercel CDN đệm tại các điểm Edge gần người dùng nhất (Singapore, Hong Kong, Nhật Bản), trả về kết quả trong **dưới 5ms**.

2. **Cơ chế Phân Tải Đa Tuyến & Hedged Racing**:
   - Phân giải đồng thời qua các DNS Upstream hàng đầu thế giới (Cloudflare, Google, Quad9, AdGuard).
   - Tự động chọn luồng phản hồi nhanh nhất, hạn chế tối đa rớt gói.

3. **Hỗ trợ 3 Chuẩn DoH**:
   - **RFC 8484 Binary POST**: `POST /dns-query` (Chuẩn iOS, Android, Firefox, Chrome).
   - **RFC 8484 Base64url GET**: `GET /dns-query?dns=<base64url>`.
   - **JSON DoH GET**: `GET /dns-query?name=google.com&type=A` (Thân thiện cURL & Debug).

---

## 🧪 Kiểm Thử Nhanh

Sau khi deploy lên Vercel, kiểm tra bằng cURL:
```bash
curl "https://ten-du-an-cua-ban.vercel.app/dns-query?name=google.com&type=A"
```
Trực tiếp trên trình duyệt: Truy cập `https://ten-du-an-cua-ban.vercel.app/` để sử dụng **Interactive DoH Resolver** và xem bảng hiệu năng thời gian thực.
