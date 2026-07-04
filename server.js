const http = require('http');
const dgram = require('dgram');
const dnsPacket = require('dns-packet');

const PORT = process.env.PORT || 3000;
const UPSTREAMS = [
  '1.1.1.1',         // Cloudflare Primary
  '8.8.8.8',         // Google Primary
  '208.67.222.222',  // OpenDNS Primary
  '1.0.0.1',         // Cloudflare Secondary
  '8.8.4.4'          // Google Secondary
];

// Stats Registry
const stats = {
  totalQueries: 0,
  cacheHits: 0,
  cacheMisses: 0,
  errors: 0,
  totalLatency: 0,
  averageLatency: 0,
  upstreamWins: {}
};
UPSTREAMS.forEach(ip => stats.upstreamWins[ip] = 0);

// In-Memory DNS Cache
// Key format: name:type:class
const cache = new Map();

// Active Pending Upstream Queries
// key: myTxId -> { resolve, reject, timeout, originalTxId }
const pendingQueries = new Map();
let nextTxId = 1;

// Initialize outgoing UDP socket for upstream racing
const udpSocket = dgram.createSocket('udp4');

udpSocket.on('message', (msg, rinfo) => {
  if (msg.length < 2) return;
  try {
    const txId = msg.readUInt16BE(0);
    const pending = pendingQueries.get(txId);
    if (pending) {
      clearTimeout(pending.timeout);
      pendingQueries.delete(txId);
      
      // Reward the winning upstream IP
      if (stats.upstreamWins[rinfo.address] !== undefined) {
        stats.upstreamWins[rinfo.address]++;
      }
      
      pending.resolve({ buffer: msg, from: rinfo.address });
    }
  } catch (err) {
    console.error('Error parsing UDP response:', err);
  }
});

udpSocket.on('error', (err) => {
  console.error('UDP socket error:', err);
});

// Helper to generate unique transaction IDs for upstream
function getNextTxId() {
  let id = nextTxId;
  while (pendingQueries.has(id)) {
    id = (id + 1) % 65536;
  }
  nextTxId = (id + 1) % 65536;
  return id;
}

// Perform DNS racing across all upstreams
function raceDNS(queryBuffer, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const originalTxId = queryBuffer.readUInt16BE(0);
    const myTxId = getNextTxId();

    // Prepare packet for upstream (replace transaction ID)
    const upstreamQuery = Buffer.from(queryBuffer);
    upstreamQuery.writeUInt16BE(myTxId, 0);

    const timeout = setTimeout(() => {
      pendingQueries.delete(myTxId);
      reject(new Error('DNS racing query timeout'));
    }, timeoutMs);

    pendingQueries.set(myTxId, {
      resolve: ({ buffer, from }) => {
        // Restore client's original transaction ID
        const responseBuffer = Buffer.from(buffer);
        responseBuffer.writeUInt16BE(originalTxId, 0);
        resolve({ responseBuffer, from });
      },
      reject,
      timeout
    });

    // Send UDP packets to all upstreams concurrently
    for (const ip of UPSTREAMS) {
      udpSocket.send(upstreamQuery, 0, upstreamQuery.length, 53, ip, (err) => {
        if (err) {
          // Non-blocking log
          // console.warn(`Failed to send DNS to upstream ${ip}:`, err.message);
        }
      });
    }
  });
}

// Helpers for DNS caching
function getCacheKey(dnsPacketObj) {
  if (!dnsPacketObj.questions || dnsPacketObj.questions.length === 0) return null;
  const q = dnsPacketObj.questions[0];
  return `${q.name.toLowerCase()}:${q.type}:${q.class || 'IN'}`;
}

function getMinTTL(dnsPacketObj) {
  let minTtl = 300; // 5 minutes default
  let found = false;

  const processRecord = (rec) => {
    if (rec && typeof rec.ttl === 'number') {
      if (!found || rec.ttl < minTtl) {
        minTtl = rec.ttl;
        found = true;
      }
    }
  };

  if (dnsPacketObj.answers) dnsPacketObj.answers.forEach(processRecord);
  if (dnsPacketObj.authorities) dnsPacketObj.authorities.forEach(processRecord);
  if (dnsPacketObj.additionals) dnsPacketObj.additionals.forEach(processRecord);

  // Constraints
  if (minTtl <= 0) minTtl = 5;       // Cache for at least 5s to avoid spamming
  if (minTtl > 86400) minTtl = 86400; // Cap at 24 hours
  return minTtl;
}

// Base64url decoder
function base64urlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

// Dynamic UUID Generator for iOS Profiles
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Periodic cleanup of expired cache entries (every 2 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of cache.entries()) {
    if (now >= val.expiresAt) {
      cache.delete(key);
    }
  }
}, 120000);

// Core DNS-over-HTTPS request processor
async function handleDoH(queryBuffer) {
  const startTime = Date.now();
  stats.totalQueries++;

  let dnsQueryObj;
  try {
    dnsQueryObj = dnsPacket.decode(queryBuffer);
  } catch (err) {
    stats.errors++;
    throw new Error('Format Error: Failed to parse DNS query');
  }

  const cacheKey = getCacheKey(dnsQueryObj);

  // 1. Cache Lookup
  if (cacheKey) {
    const cachedEntry = cache.get(cacheKey);
    if (cachedEntry && Date.now() < cachedEntry.expiresAt) {
      stats.cacheHits++;
      // Write the incoming transaction ID back into the cached buffer
      const clientTxId = queryBuffer.readUInt16BE(0);
      const responseBuffer = Buffer.from(cachedEntry.buffer);
      responseBuffer.writeUInt16BE(clientTxId, 0);

      const latency = Date.now() - startTime;
      stats.totalLatency += latency;
      stats.averageLatency = stats.totalLatency / stats.totalQueries;

      return responseBuffer;
    }
  }

  // 2. Cache Miss: Run Upstream Race
  stats.cacheMisses++;
  try {
    const { responseBuffer } = await raceDNS(queryBuffer);
    const latency = Date.now() - startTime;
    stats.totalLatency += latency;
    stats.averageLatency = stats.totalLatency / stats.totalQueries;

    // Cache the successful response
    if (cacheKey) {
      try {
        const dnsRespObj = dnsPacket.decode(responseBuffer);
        const ttl = getMinTTL(dnsRespObj);
        cache.set(cacheKey, {
          buffer: responseBuffer,
          expiresAt: Date.now() + ttl * 1000
        });
      } catch (e) {
        // Cache decoding failure - non fatal
      }
    }

    return responseBuffer;
  } catch (err) {
    stats.errors++;
    // Generate ServFail DNS response if racing fails
    try {
      const decodedQuery = dnsPacket.decode(queryBuffer);
      const servFailPacket = dnsPacket.encode({
        type: 'response',
        id: decodedQuery.id,
        flags: dnsPacket.AUTHORITATIVE_ANSWER | 2, // 2: Server failure
        questions: decodedQuery.questions
      });
      return servFailPacket;
    } catch (e) {
      throw err;
    }
  }
}

// HTTP Server Setup
const server = http.createServer(async (req, res) => {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // Endpoint 1: DoH dns-query handler
  if (parsedUrl.pathname === '/dns-query') {
    if (req.method === 'GET') {
      const dnsParam = parsedUrl.searchParams.get('dns');
      if (!dnsParam) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Missing dns parameter');
        return;
      }

      try {
        const queryBuffer = base64urlDecode(dnsParam);
        const responseBuffer = await handleDoH(queryBuffer);
        res.writeHead(200, {
          'Content-Type': 'application/dns-message',
          'Content-Length': responseBuffer.length,
          'Cache-Control': 'max-age=0'
        });
        res.end(responseBuffer);
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(err.message);
      }
    } else if (req.method === 'POST') {
      let bodyChunks = [];
      req.on('data', chunk => bodyChunks.push(chunk));
      req.on('end', async () => {
        const queryBuffer = Buffer.concat(bodyChunks);
        if (queryBuffer.length === 0) {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('Empty query body');
          return;
        }

        try {
          const responseBuffer = await handleDoH(queryBuffer);
          res.writeHead(200, {
            'Content-Type': 'application/dns-message',
            'Content-Length': responseBuffer.length,
            'Cache-Control': 'max-age=0'
          });
          res.end(responseBuffer);
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end(err.message);
        }
      });
    } else {
      res.writeHead(405, { 'Content-Type': 'text/plain' });
      res.end('Method Not Allowed');
    }
    return;
  }

  // Endpoint 2: JSON API Stats
  if (parsedUrl.pathname === '/api/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ...stats,
      cacheSize: cache.size,
      uptime: process.uptime()
    }));
    return;
  }

  // Endpoint 3: iOS Mobileconfig Generator
  if (parsedUrl.pathname === '/download-profile') {
    const host = req.headers.host || 'localhost';
    const uuid1 = generateUUID();
    const uuid2 = generateUUID();
    const configXml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>https://${host}/dns-query</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Cấu hình DNS over HTTPS tăng tốc độ truy cập Internet thông qua Antigravity DoH Proxy.</string>
            <key>PayloadDisplayName</key>
            <string>Antigravity DNS Accelerator</string>
            <key>PayloadIdentifier</key>
            <string>com.antigravity.dns.doh</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>${uuid1}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>Antigravity DNS Accelerator</string>
    <key>PayloadIdentifier</key>
    <string>com.antigravity.dns</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${uuid2}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;

    res.writeHead(200, {
      'Content-Type': 'application/x-apple-aspen-config',
      'Content-Disposition': 'attachment; filename=antigravity-dns.mobileconfig'
    });
    res.end(configXml);
    return;
  }

  // Endpoint 4: Premium Dashboard UI
  if (parsedUrl.pathname === '/') {
    const host = req.headers.host || 'localhost';
    const html = `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Antigravity DNS Accelerator</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #080b11;
            --panel-bg: rgba(17, 25, 40, 0.65);
            --border-color: rgba(255, 255, 255, 0.08);
            --accent-glow: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
            --accent-solid: #00f2fe;
            --text-color: #f3f4f6;
            --text-muted: #9ca3af;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            min-height: 100vh;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(0, 242, 254, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(79, 172, 254, 0.05) 0%, transparent 40%);
        }

        .container {
            max-width: 1100px;
            margin: 0 auto;
            padding: 40px 20px;
        }

        header {
            text-align: center;
            margin-bottom: 50px;
        }

        header h1 {
            font-size: 2.8rem;
            font-weight: 800;
            background: linear-gradient(to right, #00f2fe, #4facfe);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
            letter-spacing: -0.5px;
        }

        header p {
            color: var(--text-muted);
            font-size: 1.1rem;
            font-weight: 300;
        }

        .grid-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .stat-card {
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            backdrop-filter: blur(16px);
            border-radius: 20px;
            padding: 25px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .stat-card:hover {
            transform: translateY(-5px);
            border-color: rgba(0, 242, 254, 0.25);
            box-shadow: 0 10px 30px rgba(0, 242, 254, 0.05);
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; width: 4px; height: 100%;
            background: var(--accent-glow);
            opacity: 0;
            transition: opacity 0.3s;
        }

        .stat-card:hover::before {
            opacity: 1;
        }

        .stat-title {
            color: var(--text-muted);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 600;
            font-variant-numeric: tabular-nums;
        }

        .stat-unit {
            font-size: 0.9rem;
            color: var(--text-muted);
            font-weight: 400;
            margin-left: 4px;
        }

        .main-panel {
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            backdrop-filter: blur(16px);
            border-radius: 24px;
            padding: 40px;
            margin-bottom: 40px;
        }

        .main-panel h2 {
            font-size: 1.6rem;
            margin-bottom: 25px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .main-panel h2::before {
            content: '';
            display: inline-block;
            width: 8px; height: 24px;
            background: var(--accent-glow);
            border-radius: 4px;
        }

        .url-box {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-family: monospace;
            font-size: 1rem;
            color: var(--accent-solid);
            margin-bottom: 30px;
        }

        .btn-copy {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.85rem;
        }

        .btn-copy:hover {
            background: var(--accent-glow);
            border-color: transparent;
            color: #000;
            font-weight: 600;
        }

        .setup-steps {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        .device-accordion {
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            transition: background 0.3s;
        }

        .device-header {
            padding: 18px 25px;
            background: rgba(255, 255, 255, 0.02);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
            user-select: none;
            transition: background 0.2s;
        }

        .device-header:hover {
            background: rgba(255, 255, 255, 0.04);
        }

        .device-content {
            padding: 25px;
            background: rgba(0, 0, 0, 0.15);
            border-top: 1px solid var(--border-color);
            display: none;
            line-height: 1.6;
        }

        .device-content ol {
            padding-left: 20px;
        }

        .device-content li {
            margin-bottom: 10px;
        }

        .device-accordion.active .device-content {
            display: block;
        }

        .device-accordion.active .arrow {
            transform: rotate(180deg);
        }

        .arrow {
            transition: transform 0.3s;
            display: inline-block;
            border: solid var(--text-muted);
            border-width: 0 2px 2px 0;
            padding: 3px;
            transform: rotate(45deg);
        }

        .btn-download {
            display: inline-block;
            background: var(--accent-glow);
            color: #000;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-weight: 600;
            margin-top: 15px;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .btn-download:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 242, 254, 0.3);
        }

        .upstream-chart {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-top: 20px;
        }

        .upstream-bar-wrapper {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .upstream-name {
            width: 140px;
            font-size: 0.95rem;
            color: var(--text-muted);
        }

        .upstream-progress-bg {
            flex-grow: 1;
            height: 10px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 5px;
            overflow: hidden;
        }

        .upstream-progress-bar {
            height: 100%;
            background: var(--accent-glow);
            width: 0%;
            border-radius: 5px;
            transition: width 1s ease-in-out;
        }

        .upstream-count {
            width: 60px;
            text-align: right;
            font-variant-numeric: tabular-nums;
            font-weight: 600;
        }

        footer {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 50px;
            font-weight: 300;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Antigravity DNS Accelerator</h1>
            <p>Máy chủ phân luồng & tăng tốc internet cá nhân chạy trên Render</p>
        </header>

        <div class="grid-stats">
            <div class="stat-card">
                <div class="stat-title">Tổng truy vấn</div>
                <div class="stat-value" id="total-queries">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Tỉ lệ Cache Hit</div>
                <div class="stat-value" id="cache-hit-rate">0<span class="stat-unit">%</span></div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Độ trễ trung bình</div>
                <div class="stat-value" id="avg-latency">0<span class="stat-unit">ms</span></div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Bộ nhớ đệm</div>
                <div class="stat-value" id="cache-size">0<span class="stat-unit">records</span></div>
            </div>
        </div>

        <div class="main-panel">
            <h2>Đường dẫn DNS over HTTPS (DoH) của bạn</h2>
            <div class="url-box">
                <span id="doh-url">https://${host}/dns-query</span>
                <button class="btn-copy" onclick="copyUrl()">Sao chép</button>
            </div>

            <h2>Cấu hình thiết bị</h2>
            <div class="setup-steps">
                <!-- iOS / macOS -->
                <div class="device-accordion">
                    <div class="device-header" onclick="toggleAccordion(this)">
                        <span>Apple iOS / macOS (Tự động thiết lập hệ thống)</span>
                        <span class="arrow"></span>
                    </div>
                    <div class="device-content">
                        <p>iOS và macOS hỗ trợ cấu hình DNS mã hóa toàn hệ thống bằng DNS Profiles (.mobileconfig). Bấm vào nút bên dưới để tải profile cấu hình riêng của bạn.</p>
                        <a href="/download-profile" class="btn-download">Tải Profile Cấu Hình (.mobileconfig)</a>
                        <p style="margin-top: 15px; font-size: 0.9rem; color: var(--text-muted);">* Lưu ý: Sau khi tải về, hãy vào <strong>Cài đặt</strong> -> <strong>Đã tải về hồ sơ</strong> để kích hoạt và cài đặt profile.</p>
                    </div>
                </div>

                <!-- Android -->
                <div class="device-accordion">
                    <div class="device-header" onclick="toggleAccordion(this)">
                        <span>Google Android (Điện thoại / Máy tính bảng)</span>
                        <span class="arrow"></span>
                    </div>
                    <div class="device-content">
                        <p>Hệ điều hành Android hỗ trợ Private DNS (DNS-over-TLS). Do Render chỉ hỗ trợ cổng HTTPS (DoH), bạn cần dùng một app trung gian như <strong>Nebulo</strong> hoặc <strong>Intra</strong> để kết nối:</p>
                        <ol style="margin-top: 10px;">
                            <li>Tải và cài đặt ứng dụng <strong>Intra</strong> hoặc <strong>Nebulo</strong> từ Google Play Store.</li>
                            <li>Mở cài đặt của ứng dụng, chọn mục cấu hình DNS tùy chỉnh (Custom DoH Server).</li>
                            <li>Nhập đường dẫn DoH của bạn ở trên vào.</li>
                            <li>Bấm kích hoạt để chạy VPN DNS cục bộ nhằm tăng tốc tất cả ứng dụng.</li>
                        </ol>
                    </div>
                </div>

                <!-- Browsers -->
                <div class="device-accordion">
                    <div class="device-header" onclick="toggleAccordion(this)">
                        <span>Trình duyệt (Chrome / Firefox / Edge / Brave)</span>
                        <span class="arrow"></span>
                    </div>
                    <div class="device-content">
                        <p>Để tăng tốc độ lướt web trên máy tính, bạn có thể chỉ cấu hình DNS an toàn trực tiếp trên trình duyệt lướt web:</p>
                        <h4 style="margin-top: 10px; font-size: 1rem;">Google Chrome / Brave / Edge:</h4>
                        <ol>
                            <li>Vào <strong>Cài đặt (Settings)</strong> -> <strong>Quyền riêng tư và bảo mật (Privacy & Security)</strong> -> <strong>Bảo mật (Security)</strong>.</li>
                            <li>Tìm mục <strong>Sử dụng DNS an toàn (Use Secure DNS)</strong>.</li>
                            <li>Chọn <strong>Với: Tùy chỉnh (With: Custom)</strong> và nhập đường dẫn DoH ở trên vào.</li>
                        </ol>
                        <h4 style="margin-top: 15px; font-size: 1rem;">Mozilla Firefox:</h4>
                        <ol>
                            <li>Vào <strong>Cài đặt (Settings)</strong> -> <strong>Quyền riêng tư & Bảo mật (Privacy & Security)</strong>.</li>
                            <li>Kéo xuống cuối tìm mục <strong>DNS qua HTTPS (DNS over HTTPS)</strong>.</li>
                            <li>Chọn chế độ <strong>Bảo vệ tối đa (Max Protection)</strong>, chọn nhà cung cấp: <strong>Tùy chỉnh (Custom)</strong> và điền đường dẫn DoH ở trên vào.</li>
                        </ol>
                    </div>
                </div>

                <!-- Windows 11 -->
                <div class="device-accordion">
                    <div class="device-header" onclick="toggleAccordion(this)">
                        <span>Microsoft Windows 11</span>
                        <span class="arrow"></span>
                    </div>
                    <div class="device-content">
                        <p>Windows 11 hỗ trợ cấu hình DoH hệ thống nhưng yêu cầu bổ sung cấu hình IP để kích hoạt mẫu:</p>
                        <ol>
                            <li>Vào <strong>Settings (Cài đặt)</strong> -> <strong>Network & internet (Mạng & internet)</strong> -> <strong>Wi-Fi</strong> hoặc <strong>Ethernet</strong>.</li>
                            <li>Tìm mục <strong>DNS server assignment</strong>, bấm <strong>Edit</strong>.</li>
                            <li>Chuyển sang <strong>Manual</strong>, bật <strong>IPv4</strong>.</li>
                            <li>Ở phần <strong>Preferred DNS</strong>, nhập IP một upstream đại diện (ví dụ: <code>1.1.1.1</code>).</li>
                            <li>Ở phần <strong>Preferred DNS encryption</strong>, chọn <strong>Encrypted only (DNS over HTTPS)</strong>.</li>
                            <li>Tìm mục mẫu liên kết DoH và điền đường dẫn DoH ở trên vào nếu có, hoặc Windows sẽ tự nhận dạng.</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <div class="main-panel">
            <h2>Thống kê tốc độ Upstream DNS Racing</h2>
            <div class="upstream-chart" id="upstream-chart">
                <!-- Rendered dynamically -->
            </div>
        </div>

        <footer>
            <p>Được phát triển bởi Antigravity Coding Engine v3. Trạng thái server: Hoạt động ổn định.</p>
        </footer>
    </div>

    <script>
        function toggleAccordion(el) {
            const acc = el.parentElement;
            acc.classList.toggle('active');
        }

        function copyUrl() {
            const urlText = document.getElementById('doh-url').innerText;
            navigator.clipboard.writeText(urlText).then(() => {
                const btn = document.querySelector('.btn-copy');
                btn.innerText = 'Đã chép!';
                btn.style.background = '#00f2fe';
                btn.style.color = '#000';
                setTimeout(() => {
                    btn.innerText = 'Sao chép';
                    btn.style.background = '';
                    btn.style.color = '';
                }, 2000);
            });
        }

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                
                // Cập nhật số liệu
                document.getElementById('total-queries').innerText = data.totalQueries.toLocaleString();
                
                const hitRate = data.totalQueries > 0 ? Math.round((data.cacheHits / data.totalQueries) * 100) : 0;
                document.getElementById('cache-hit-rate').innerHTML = hitRate + '<span class="stat-unit">%</span>';
                
                const avgLat = Math.round(data.averageLatency);
                document.getElementById('avg-latency').innerHTML = avgLat + '<span class="stat-unit">ms</span>';
                
                document.getElementById('cache-size').innerHTML = data.cacheSize + '<span class="stat-unit">records</span>';

                // Vẽ bảng Upstream Racing
                const chartContainer = document.getElementById('upstream-chart');
                chartContainer.innerHTML = '';
                
                const wins = data.upstreamWins;
                const totalWins = Object.values(wins).reduce((a, b) => a + b, 0);

                // Sắp xếp các upstream theo số lượt thắng
                const sortedUpstreams = Object.entries(wins).sort((a, b) => b[1] - a[1]);

                sortedUpstreams.forEach(([ip, count]) => {
                    const percent = totalWins > 0 ? Math.round((count / totalWins) * 100) : 0;
                    
                    const wrapper = document.createElement('div');
                    wrapper.className = 'upstream-bar-wrapper';
                    
                    let displayName = ip;
                    if (ip === '1.1.1.1' || ip === '1.0.0.1') displayName = 'Cloudflare (' + ip + ')';
                    else if (ip === '8.8.8.8' || ip === '8.8.4.4') displayName = 'Google (' + ip + ')';
                    else if (ip === '208.67.222.222' || ip === '208.67.220.220') displayName = 'OpenDNS (' + ip + ')';

                    wrapper.innerHTML = \`
                        <div class="upstream-name">\${displayName}</div>
                        <div class="upstream-progress-bg">
                            <div class="upstream-progress-bar" style="width: \${percent}%"></div>
                        </div>
                        <div class="upstream-count">\${count} lượt</div>
                    \`;
                    chartContainer.appendChild(wrapper);
                });

            } catch (err) {
                console.error('Error fetching stats:', err);
            }
        }

        // Fetch stats immediately and then refresh every 3 seconds
        fetchStats();
        setInterval(fetchStats, 3000);
    </script>
</body>
</html>`;

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  }
});

// Start Server
server.listen(PORT, () => {
  console.log(`Antigravity DNS Accelerator running on http://localhost:${PORT}`);
  console.log(`Accepting DoH requests at /dns-query`);
  console.log(`Active upstream resolvers: ${UPSTREAMS.join(', ')}`);
});
