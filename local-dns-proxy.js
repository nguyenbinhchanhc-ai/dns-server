const dgram = require('dgram');
const https = require('https');

// Đường dẫn DoH cá nhân trên Render của bạn
const DOH_URL = 'https://dns-server-4ys7.onrender.com/dns-query';
const LOCAL_PORT = 53; // Cổng DNS truyền thống (Cần chạy với quyền Admin/Root)

const server = dgram.createSocket('udp4');

server.on('message', (msg, rinfo) => {
  // Parse URL DoH để lấy hostname và path
  const url = new URL(DOH_URL);
  
  const options = {
    hostname: url.hostname,
    port: 443,
    path: url.pathname + url.search,
    method: 'POST',
    headers: {
      'Content-Type': 'application/dns-message',
      'Content-Length': msg.length
    },
    timeout: 3000 // Timeout 3 giây
  };

  const req = https.request(options, (res) => {
    if (res.statusCode !== 200) {
      // console.error(`DoH server returned status ${res.statusCode}`);
      return;
    }

    let chunks = [];
    res.on('data', chunk => chunks.push(chunk));
    res.on('end', () => {
      const responseBuffer = Buffer.concat(chunks);
      server.send(responseBuffer, 0, responseBuffer.length, rinfo.port, rinfo.address, (err) => {
        if (err) {
          console.error('Failed to send UDP response back to client:', err);
        }
      });
    });
  });

  req.on('error', (err) => {
    console.error('HTTPS DoH request error:', err.message);
  });

  req.on('timeout', () => {
    req.destroy();
  });

  req.write(msg);
  req.end();
});

server.on('error', (err) => {
  console.error('Local UDP socket error:', err);
  if (err.code === 'EACCES') {
    console.error(`\n[LỖI QUYỀN TRUY CẬP]: Cổng ${LOCAL_PORT} yêu cầu quyền Administrator (Admin) để chạy.`);
    console.error('Hãy chạy Terminal/CMD bằng quyền "Run as Administrator" và thử lại.');
  }
});

server.on('listening', () => {
  const address = server.address();
  console.log('=====================================================');
  console.log(` Máy chủ chuyển đổi DNS-to-DoH đang chạy cục bộ.`);
  console.log(` Cổng lắng nghe: UDP ${address.address}:${address.port}`);
  console.log(` Đang chuyển tiếp truy vấn tới: ${DOH_URL}`);
  console.log('=====================================================');
  console.log('Bạn có thể cấu hình IP máy tính này làm DNS cho TV, Router, Console...');
});

// Lắng nghe trên mọi interface mạng (0.0.0.0) để các thiết bị trong mạng LAN truy cập được
server.bind(LOCAL_PORT, '0.0.0.0');
