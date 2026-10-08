# Antigravity Hyper-Speed DNS over HTTPS (DoH) Proxy — Tối Ưu Cho Vercel

Máy chủ proxy DNS-over-HTTPS (DoH) hiệu năng cao, thuật toán chia tải nhạy trễ thông minh (Adaptive Latency-Aware Hedged Racing), loại bỏ nghẽn tải, đệm RAM + SWR (Stale-While-Revalidate), tối ưu hóa hoàn toàn cho **Vercel Serverless**.

---

## ⚡ Các Tối Ưu Quan Trọng Đã Triển Khai:

### 1. Khắc phục triệt để lỗi không gom được toàn bộ truy vấn / Nghẽn truy vấn:
- **Nguyên nhân gây nghẽn trước đây**:
  - Hàng đợi socket `httpsAgent.maxSockets` bị giới hạn ở 50 khiến hàng loạt truy vấn DNS đồng thời từ điện thoại (khi mở trang web có 50–100 request song song) bị xếp hàng chờ, dẫn đến hết hạn thời gian (timeout) và bị rớt truy vấn.
  - Upstream `Quad9` (9.9.9.9) trả về HTTP 505 và `Mullvad` bị socket hang up liên tục khiến các truy vấn bị kẹt chờ timeout 2000ms.
  - Request coalescing (gom nhóm truy vấn trùng) trước đây chưa có safety timeout, nếu truy vấn đầu tiên gặp server chậm sẽ kéo theo toàn bộ các truy vấn cùng tên miền bị treo.
- **Giải pháp đã xử lý**:
  - Đặt `maxSockets: Infinity` và `maxFreeSockets: 128` cho `httpsAgent`: Mọi truy vấn đều có socket HTTPS ngay lập tức, không còn hàng đợi nghẽn.
  - Loại bỏ các server lỗi (Quad9, Mullvad), giữ lại danh mục **9 upstream quốc tế siêu tốc 100% phản hồi HTTP 200** (Google, Cloudflare, OpenDNS, AdGuard, DNS.SB, ControlD).
  - Bổ sung **Safety Timeout (600ms)** cho Request Coalescing: Nếu truy vấn đang chạy gặp chậm trễ, các truy vấn sau sẽ tự động bứt ra để tự đua upstream mà không bị kẹt.
  - Mở rộng phủ sóng 100% các endpoint: `/dns-query`, `/query`, `/resolve`, `/doh`, `/dns`, `/api/dns-query` trong cả `vercel.json` và code backend.

### 2. Thuật toán chia tải thông minh, nhạy trễ và ổn định (Smart Load Balancer):
- **Cơ chế tính điểm linh hoạt theo thời gian thực (PEWMA Score)**:
  `Score = Real_EMA_Latency + (Active_Queries × 12) + Error_Penalty`
  *(Điểm càng thấp = Máy chủ càng nhanh và ít tải)*
- **Đua 3 đường truyền song song (Hedged Racing) kèm hủy ngay lập tức các yêu cầu thua cuộc**:
  - Luôn chọn 3 ứng viên tốt nhất để cùng phân giải.
  - Khi máy chủ nhanh nhất về đích đầu tiên, hệ thống gửi tín hiệu **AbortSignal hủy ngay lập tức các yêu cầu còn lại**, giải phóng socket và băng thông mạng.
- **Circuit Breaker tự động cách ly máy chủ suy giảm**:
  - Nếu một upstream bị lỗi liên tiếp ≥ 3 lần, chuyển trạng thái sang `Degraded`, ≥ 5 lần chuyển sang `Offline`.
  - Bộ kiểm tra Canary tự động thăm dò máy chủ lỗi ngầm mỗi 30 giây để phục hồi tự động khi máy chủ khỏe lại.

---

## 🚀 Cách Cập Nhật Lên Vercel Ngay Lập Tức:

Mở terminal trên máy tính của bạn trong thư mục dự án và chạy:

```bash
git add .
git commit -m "Optimize DoH concurrency, remove bottlenecks, smart hedged load balancing"
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
6. **Xong!** Toàn bộ iPhone sẽ tự động chạy qua máy chủ DoH bảo mật, tốc độ cao, không hao pin, không cần cài VPN.

### Cách 2: Cài đặt thủ công bằng URL DoH
- **URL DoH chuẩn**:
  ```
  https://ten-du-an.vercel.app/dns-query
  ```
  *(Hoặc `https://ten-du-an.vercel.app/api/dns-query`)*

- **Trình duyệt (Chrome / Edge / Firefox / Brave)**:
  - Vào *Cài đặt (Settings)* ➔ *Quyền riêng tư và bảo mật* ➔ *Sử dụng DNS an toàn*.
  - Chọn *Tùy chỉnh (Custom)* và dán URL trên vào.

- **Ứng dụng DoH (Android Private DNS / DNSCloak / AdGuard / Intra)**:
  - Dán URL `https://ten-du-an.vercel.app/dns-query` vào cấu hình.
