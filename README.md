# Antigravity Hyper-Speed DNS over HTTPS (DoH) Proxy — Tối Ưu Cho Vercel

Máy chủ proxy DNS-over-HTTPS (DoH) hiệu năng cao, thuật toán chia tải nhạy trễ (Hedged Racing Multi-Upstream), hỗ trợ đệm RAM + SWR (Stale-While-Revalidate), tối ưu hóa hoàn toàn cho **Vercel Serverless**.

---

## 🛠️ Nguyên Nhân Gây Ra Lỗi Mất Internet Trên Vercel Trước Đó & Đã Được Khắc Phục:

- **Nguyên nhân cốt lõi**: Trong phiên bản trước, quy tắc rewrite `/(.*) -> /api/index` trên Vercel khiến mọi yêu cầu đến `/dns-query` (hoặc POST binary từ iOS/Android) bị gán `req.url` thành `/api/index`. Do đường dẫn không khớp, máy chủ đã trả về **mã HTML (trang web dashboard)** với mã 200 OK thay vì gói tin nhị phân chuẩn `application/dns-message`.
- Khi iPhone hoặc ứng dụng DNS nhận được chuỗi HTML thay vì gói DNS hợp lệ, hệ điều hành lập tức báo lỗi cấu hình DNS và ngắt kết nối Internet toàn bộ máy.
- **Giải pháp triệt để đã triển khai**:
  1. Tạo router chuyên trách `/api/dns-query.js` với cờ `bodyParser: false` để giữ nguyên luồng dữ liệu nhị phân RFC 8484 nguyên bản.
  2. Bổ sung cơ chế phát hiện DoH thông minh đa tầng: Mọi request có `Content-Type: application/dns-message`, `Accept: application/dns-message` hoặc tham số `?dns=` / `?name=` đều được điều hướng thẳng vào bộ máy phân giải DoH, **tuyệt đối không bao giờ trả về HTML cho client DNS**.
  3. Cung cấp file cấu hình **1-chạm cho iPhone / iPad / Mac (`/profile.mobileconfig`)**: Tải trực tiếp qua Safari và kích hoạt ngay mà không cần cài thêm bất kỳ ứng dụng nào!

---

## 🚀 Cách Cập Nhật Lên Vercel Ngay Lập Tức:

Mở terminal trên máy tính của bạn trong thư mục dự án và chạy:

```bash
git add .
git commit -m "Fix DoH routing, add native iOS mobileconfig and api/dns-query handler"
git push
```

Vercel sẽ tự động build và deploy phiên bản mới trong vòng ~15 giây!

---

## 📱 Hướng Dẫn Cài Đặt Vào Thiết Bị:

### Cách 1: Cài đặt 1-chạm vào iPhone / iPad / Mac (Khuyên dùng nhất - Không cần cài app)
1. Dùng trình duyệt **Safari** trên iPhone truy cập vào trang web Vercel của bạn:
   ```
   https://ten-du-an.vercel.app
   ```
2. Bấm nút **"📥 Tải Profile iOS (.mobileconfig)"** (hoặc truy cập thẳng `https://ten-du-an.vercel.app/profile.mobileconfig`).
3. Chọn **Cho phép (Allow)** khi có thông báo tải hồ sơ cấu hình.
4. Mở **Cài đặt (Settings)** trên iPhone ➔ bấm vào mục **"Đã tải về hồ sơ" (Profile Downloaded)** ở ngay đầu màn hình.
5. Bấm **Cài đặt (Install)** ở góc trên bên phải và xác nhận mật khẩu máy.
6. **Xong!** Toàn bộ iPhone sẽ tự động chạy qua máy chủ DoH bảo mật, không hao pin, không cần bật app VPN chạy ngầm.

### Cách 2: Cài đặt thủ công bằng URL DoH
- **URL DoH chuẩn**:
  ```
  https://ten-du-an.vercel.app/dns-query
  ```
  *(Hoặc `https://ten-du-an.vercel.app/api/dns-query`)*

- **Trình duyệt (Chrome / Edge / Firefox / Brave)**:
  - Vào *Cài đặt (Settings)* ➔ *Quyền riêng tư và bảo mật* ➔ *Sử dụng DNS an toàn*.
  - Chọn *Tùy chỉnh (Custom)* và dán URL trên vào.

- **Ứng dụng DoH (DNSCloak, AdGuard, Intra)**:
  - Dán URL `https://ten-du-an.vercel.app/dns-query` vào mục DoH Server URL.

---

## 🧪 Kiểm Tra Hoạt Động Của Máy Chủ:

Kiểm tra bằng cURL (trả về JSON):
```bash
curl "https://ten-du-an.vercel.app/dns-query?name=google.com&type=A"
```

Kiểm tra gói tin nhị phân RFC 8484 (POST):
```bash
curl -X POST "https://ten-du-an.vercel.app/dns-query" \
  -H "Content-Type: application/dns-message" \
  -H "Accept: application/dns-message" \
  --data-binary @-
```
