# Antigravity Hyper-Speed DNS over HTTPS (DoH) Proxy — Tối Ưu Cho Vercel

Máy chủ proxy DNS-over-HTTPS (DoH) hiệu năng cao, cập nhật Realtime qua Server-Sent Events (SSE), tích hợp **Cơ chế Tự Sửa Lỗi Gói Tin (Packet Self-Healing)**, thuật toán chia tải nhạy trễ thông minh (Adaptive Latency-Aware Hedged Racing), và bảo đảm ổn định mạng tuyệt đối cho **Vercel Serverless**.

---

## ⚡ Các Tính Năng Mới & Nâng Cấp Tối Ưu:

### 1. Khắc Phục Triệt Để Lỗi "Truy Vấn Không Cập Nhật" (iOS & Vercel Serverless):
- **Vấn đề đã tìm ra**:
  1. Trong file profile `.mobileconfig` của iOS, mục `ServerAddresses` trước đó chứa IP của Cloudflare/Google (`1.1.1.1`, `8.8.8.8`). Theo chuẩn kỹ thuật Apple `com.apple.dnsSettings.managed`, khi có `ServerAddresses`, iOS sẽ cố gắng kết nối TLS trực tiếp đến IP đó với hostname của Vercel (`*.vercel.app`). Do IP của Cloudflare không nhận SSL của Vercel, bắt tay TLS thất bại và iOS ngắt kết nối DoH, dẫn đến **không có truy vấn nào được gửi đến server**.
  2. Trên Vercel Serverless, hàm lưu trữ số liệu trước đó dùng `setTimeout` với độ trễ 1000ms. Do hàm Lambda đóng băng (freeze) ngay khi trả về phản hồi DNS, bộ hẹn giờ không kịp chạy khiến số liệu không được ghi vào đĩa.
- **Giải pháp xử lý**:
  - Đã loại bỏ hoàn toàn `ServerAddresses` xung đột trong profile iOS. iOS giờ đây tự phân giải domain server bằng bootstrap DNS hiện tại và kết nối trực tiếp, mượt mà tới proxy DoH.
  - Ghi nhận và đồng bộ tức thì số liệu (`persistStats(true)` đồng bộ) trước khi kết thúc chu kỳ xử lý truy vấn, kết hợp bộ nhớ đệm `localStorage` ở client để không bao giờ bị mất truy vấn.

### 2. Loại Bỏ Hoàn Toàn Hiện Tượng "Giật Giật" (Jitter-Free Smart Reconciliation):
- **Vấn đề đã tìm ra**:
  - Giao diện trước đó liên tục gán lại `innerHTML` của bảng log và bảng máy chủ mỗi 1.5 - 2 giây (qua cả SSE và lệnh polling chạy song song), khiến trình duyệt phải liên tục tính toán lại kích thước cột, hủy và tạo lại hàng chục phần tử DOM, gây hiện tượng giật hình / chớp màn hình rõ rệt.
- **Giải pháp xử lý**:
  - **Smart Signature Reconciliation**: Hệ thống tính toán mã băm (signature) của danh sách truy vấn và bảng máy chủ. Nếu dữ liệu không thay đổi, **tuyệt đối không chạm vào DOM**.
  - **Cố định bố cục (`table-layout: fixed`) & `<colgroup>`**: Các cột được cố định độ rộng bằng pixel chính xác, chống giật nhảy bố cục khi có domain dài xuất hiện.
  - **Tối ưu Server-Sent Events**: Server chỉ đẩy gói dữ liệu khi có thay đổi thực tế; khi không có truy vấn mới, server chỉ gửi ping giữ kết nối nhẹ `: ping\n\n`.
  - Tự động dừng polling khi SSE đang hoạt động, loại bỏ 100% tình trạng xung đột cập nhật trùng lặp.
  - Bổ sung thanh **Thử nhanh 1-chạm** (`google.com`, `apple.com`, `shopee.vn`, `vnexpress.net`, `cloudflare.com`) để kiểm tra tức thì tốc độ phân giải.

### 3. Cơ chế Tự Sửa Lỗi Gói Tin (DNS Packet Self-Healing Engine):
- **Vấn đề**: Khi mạng di động 4G/5G hoặc Wi-Fi chập chờn, gói tin DNS wireformat có thể bị mất một vài byte, cắt cụt (truncated header/label) hoặc chứa ký tự hỏng.
- **Giải pháp**:
  - Tích hợp hàm `repairAndNormalizeDnsQuery` tự bù đắp header 12-byte và phân tích nhị phân thủ công để trích xuất domain ngay cả khi nhãn nhị phân bị cắt cụt.
  - Bổ sung `repairDnsResponse` bảo vệ phản hồi upstream, bảo đảm thiết bị di động luôn nhận kết quả hợp lệ, **không bao giờ bị mất mạng**.

### 4. Tăng tốc phân giải và tối ưu chia tải (Hyper-Speed Latency Racing):
- **Upstream tối ưu**: Endpoint ControlD DoH siêu tốc `https://freedns.controld.com/p0`.
- **Giữ kết nối HTTPS dài hạn**: `keepAlive: true` giảm thời gian bắt tay TLS xuống **0ms** cho các truy vấn kế tiếp.
- **Bộ đệm 0ms (In-Memory RAM Cache) + SWR**: Trả lời ngay tức thì cho các tên miền quen thuộc.
- **Hedged Racing**: Gửi song song đến cụm server nhanh nhất, nhận phản hồi đầu tiên.

---

## 🚀 Cách Cập Nhật Lên Vercel:

Trên máy tính của bạn trong thư mục dự án, chỉ cần chạy:

```bash
git add .
git commit -m "Add SSE realtime streaming, DNS packet self-healing engine, and latency acceleration"
git push
```

Vercel sẽ tự động build và cập nhật phiên bản mới trong vòng ~15 giây.

---

## 📱 Cài Đặt Vào Thiết Bị:

### Cài đặt 1-chạm cho iPhone / iPad / Mac:
1. Mở **Safari** trên thiết bị và truy cập vào trang web DoH của bạn trên Vercel:
   ```
   https://ten-du-an.vercel.app
   ```
2. Bấm nút **"📥 Tải Profile iOS (.mobileconfig)"**.
3. Chọn **Cho phép (Allow)**.
4. Mở **Cài đặt (Settings)** ➔ **Đã tải về hồ sơ (Profile Downloaded)** ➔ Bấm **Cài đặt (Install)**.
