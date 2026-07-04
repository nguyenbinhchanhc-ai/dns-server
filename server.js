const http = require('http');
const dgram = require('dgram');
const dnsPacket = require('dns-packet');

const PORT = process.env.PORT || 3000;

// Expanded Upstream DNS Servers List
const UPSTREAMS = [
  { ip: '1.1.1.1', name: 'Cloudflare Primary' },
  { ip: '1.0.0.1', name: 'Cloudflare Secondary' },
  { ip: '8.8.8.8', name: 'Google Primary' },
  { ip: '8.8.4.4', name: 'Google Secondary' },
  { ip: '9.9.9.9', name: 'Quad9 Security' },
  { ip: '149.112.112.112', name: 'Quad9 Assist' },
  { ip: '208.67.222.222', name: 'OpenDNS Home' },
  { ip: '208.67.220.220', name: 'OpenDNS Custom' },
  { ip: '94.140.14.14', name: 'AdGuard Default' },
  { ip: '76.76.2.0', name: 'ControlD Unfiltered' }
];

// Stats Registry
const stats = {
  totalQueries: 0,
  cacheHits: 0,
  cacheMisses: 0,
  errors: 0,
  totalLatency: 0,
  averageLatency: 0
};

// Upstream Performance & Health Registry (Adaptive with EMA & Penalty)
const upstreamStates = UPSTREAMS.map(dns => ({
  ip: dns.ip,
  name: dns.name,
  pings: [],              // Last 5 ping latencies for sliding window
  successCount: 0,
  failCount: 0,
  avgLatency: 120,        // Active ping latency average
  lossRate: 0,
  
  // Real-world client query performance
  realAvgLatency: 0,      // Exponential Moving Average (EMA) of real queries
  realQueriesCount: 0,    // Total real queries sent
  realErrorsCount: 0,     // Total real query errors/timeouts
  
  penalty: 0,             // Active penalty (ms) for errors, decays over time
  score: 120,             // Routing score = avgLatency + lossRate*5 + penalty (lower is better)
  routedQueries: 0,       // Total client queries won by this upstream
  status: 'Healthy'       // 'Healthy', 'Warning', 'Offline'
}));

// Pre-sorted active candidates for O(1) routing
let activeCandidates = [];

function updateCandidates() {
  const sorted = [...upstreamStates]
    .filter(s => s.status !== 'Offline')
    .sort((a, b) => a.score - b.score);
    
  activeCandidates = sorted.length >= 2 
    ? sorted.slice(0, 2) 
    : (sorted.length > 0 ? sorted : upstreamStates.slice(0, 2));
}

// In-Memory DNS Cache (Key: name:type:class)
const cache = new Map();

// Active Pending Upstream Queries (UDP mapping)
// key: myTxId -> { resolve, reject, timeout, originalTxId }
const pendingQueries = new Map();
let nextTxId = 1;

// Initialize outgoing UDP socket for upstream routing & active health checks
const udpSocket = dgram.createSocket('udp4');

udpSocket.on('message', (msg, rinfo) => {
  if (msg.length < 2) return;
  try {
    const txId = msg.readUInt16BE(0);
    const pending = pendingQueries.get(txId);
    if (pending) {
      clearTimeout(pending.timeout);
      pendingQueries.delete(txId);
      pending.resolve({ buffer: msg, from: rinfo.address });
    }
  } catch (err) {
    console.error('Error handling UDP DNS response:', err);
  }
});

udpSocket.on('error', (err) => {
  console.error('UDP socket error:', err);
});

// Unique transaction ID generator
function getNextTxId() {
  let id = nextTxId;
  while (pendingQueries.has(id)) {
    id = (id + 1) % 65536;
  }
  nextTxId = (id + 1) % 65536;
  return id;
}

// Active Health Check: Ping an upstream with a lightweight query
function pingUpstream(ip) {
  return new Promise((resolve) => {
    const txId = getNextTxId();
    
    // Create standard SOA query for root zone as a small ping packet
    const pingPacket = dnsPacket.encode({
      type: 'query',
      id: txId,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: 'SOA',
        name: '.'
      }]
    });

    const startTime = Date.now();
    const timeout = setTimeout(() => {
      pendingQueries.delete(txId);
      resolve({ success: false, latency: 1000 });
    }, 1500); // 1.5 seconds timeout

    pendingQueries.set(txId, {
      resolve: () => {
        clearTimeout(timeout);
        const latency = Date.now() - startTime;
        resolve({ success: true, latency });
      },
      reject: () => {
        clearTimeout(timeout);
        resolve({ success: false, latency: 1000 });
      },
      timeout
    });

    udpSocket.send(pingPacket, 0, pingPacket.length, 53, ip, (err) => {
      if (err) {
        clearTimeout(timeout);
        pendingQueries.delete(txId);
        resolve({ success: false, latency: 1000 });
      }
    });
  });
}

// Perform health checks on all upstreams in parallel
async function performHealthChecks() {
  await Promise.all(upstreamStates.map(async (state) => {
    const res = await pingUpstream(state.ip);
    
    // Update sliding window (last 5 results)
    if (res.success) {
      state.pings.push(res.latency);
      state.successCount++;
    } else {
      state.pings.push(1000); // Penalty latency for packet loss
      state.failCount++;
    }
    if (state.pings.length > 5) {
      state.pings.shift();
    }

    // Calculations
    const validPings = state.pings.filter(p => p !== 1000);
    state.avgLatency = validPings.length > 0 
      ? Math.round(validPings.reduce((a, b) => a + b, 0) / validPings.length)
      : 1000;

    const lostCount = state.pings.filter(p => p === 1000).length;
    state.lossRate = Math.round((lostCount / state.pings.length) * 100);

    // Decay current penalty by 50% on every active health check tick
    state.penalty = Math.max(0, Math.round(state.penalty * 0.5));

    // Score = avgLatency + packet loss penalty + active penalty
    state.score = state.avgLatency + (state.lossRate * 5) + state.penalty;

    // Determine status
    if (state.lossRate >= 60) {
      state.status = 'Offline';
    } else if (state.lossRate >= 20 || state.avgLatency > 250 || state.penalty > 200) {
      state.status = 'Warning';
    } else {
      state.status = 'Healthy';
    }
  }));

  updateCandidates();
}

// Perform initial check, set candidates list and schedule every 25 seconds
performHealthChecks().then(() => {
  updateCandidates();
});
setInterval(performHealthChecks, 25000);

// Perform DNS racing on pre-sorted top 2 healthiest servers
function raceDNS(queryBuffer, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const candidates = activeCandidates;
    const originalTxId = queryBuffer.readUInt16BE(0);
    const myTxId = getNextTxId();

    const upstreamQuery = Buffer.from(queryBuffer);
    upstreamQuery.writeUInt16BE(myTxId, 0);

    const startTime = Date.now();

    const timeout = setTimeout(() => {
      pendingQueries.delete(myTxId);
      
      // Apply timeout penalties to all queried candidates
      candidates.forEach(state => {
        state.realErrorsCount++;
        state.penalty = Math.min(1000, state.penalty + 250); // Instant 250ms penalty
        state.score = state.avgLatency + (state.lossRate * 5) + state.penalty;
      });
      updateCandidates();

      reject(new Error('DNS racing query timeout'));
    }, timeoutMs);

    pendingQueries.set(myTxId, {
      resolve: ({ buffer, from }) => {
        clearTimeout(timeout);
        const latency = Date.now() - startTime;
        
        const responseBuffer = Buffer.from(buffer);
        responseBuffer.writeUInt16BE(originalTxId, 0);
        
        // Track stats & calculate EMA for the winner
        const winner = upstreamStates.find(s => s.ip === from);
        if (winner) {
          winner.routedQueries++;
          
          // Exponential Moving Average (EMA) with alpha = 0.3
          const alpha = 0.3;
          winner.realAvgLatency = winner.realQueriesCount === 0 
            ? latency 
            : Math.round(alpha * latency + (1 - alpha) * winner.realAvgLatency);
          winner.realQueriesCount++;
          
          // Reduce penalty slightly for successful real query
          winner.penalty = Math.max(0, winner.penalty - 25);
          winner.score = winner.avgLatency + (winner.lossRate * 5) + winner.penalty;
        }

        updateCandidates();
        resolve({ responseBuffer, from });
      },
      reject: (err) => {
        clearTimeout(timeout);
        pendingQueries.delete(myTxId);
        
        // Apply error penalties to all queried candidates
        candidates.forEach(state => {
          state.realErrorsCount++;
          state.penalty = Math.min(1000, state.penalty + 200);
          state.score = state.avgLatency + (state.lossRate * 5) + state.penalty;
        });
        updateCandidates();

        reject(err);
      },
      timeout
    });

    // Send UDP queries in parallel (O(1) candidates selection)
    candidates.forEach(state => {
      udpSocket.send(upstreamQuery, 0, upstreamQuery.length, 53, state.ip, (err) => {
        if (err) {
          // Instant send failure penalty
          state.realErrorsCount++;
          state.penalty = Math.min(1000, state.penalty + 100);
          state.score = state.avgLatency + (state.lossRate * 5) + state.penalty;
          updateCandidates();
        }
      });
    });
  });
}

// Helpers for DNS caching
function getCacheKey(dnsPacketObj) {
  if (!dnsPacketObj.questions || dnsPacketObj.questions.length === 0) return null;
  const q = dnsPacketObj.questions[0];
  return `${q.name.toLowerCase()}:${q.type}:${q.class || 'IN'}`;
}

function getMinTTL(dnsPacketObj) {
  let minTtl = 300;
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

  if (minTtl <= 0) minTtl = 5;
  if (minTtl > 86400) minTtl = 86400;
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
    const { responseBuffer, from } = await raceDNS(queryBuffer);
    const latency = Date.now() - startTime;
    stats.totalLatency += latency;
    stats.averageLatency = stats.totalLatency / stats.totalQueries;

    // Cache successful response
    if (cacheKey) {
      try {
        const dnsRespObj = dnsPacket.decode(responseBuffer);
        const ttl = getMinTTL(dnsRespObj);
        cache.set(cacheKey, {
          buffer: responseBuffer,
          expiresAt: Date.now() + ttl * 1000
        });
      } catch (e) {
        // Non-fatal cache failure
      }
    }

    return responseBuffer;
  } catch (err) {
    stats.errors++;
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

// HTTP Server
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // Endpoint 1: DoH Handler
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

  // Endpoint 2: JSON API Stats (Includes detailed load balance & adaptive parameters)
  if (parsedUrl.pathname === '/api/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ...stats,
      upstreams: upstreamStates,
      cacheSize: cache.size,
      uptime: process.uptime()
    }));
    return;
  }

  // Endpoint 3: iOS Profile Downloader
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
                <key>ServerAddresses</key>
                <array>
                    <string>1.1.1.1</string>
                    <string>1.0.0.1</string>
                    <string>8.8.8.8</string>
                    <string>8.8.4.4</string>
                    <string>9.9.9.9</string>
                </array>
                <key>ProhibitFallback</key>
                <true/>
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

  // Endpoint 4: Premium Web Dashboard UI
  if (parsedUrl.pathname === '/') {
    const host = req.headers.host || 'localhost';
    const html = `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Antigravity Adaptive DNS Load Balancer</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #05070f;
            --panel-bg: rgba(10, 15, 30, 0.65);
            --border-color: rgba(255, 255, 255, 0.05);
            --accent-glow: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
            --accent-solid: #00f2fe;
            --text-color: #f3f4f6;
            --text-muted: #9ca3af;
            
            --color-healthy: #00ffaa;
            --color-warning: #ffb800;
            --color-offline: #ff3b30;
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
                radial-gradient(circle at 10% 15%, rgba(0, 242, 254, 0.04) 0%, transparent 35%),
                radial-gradient(circle at 90% 85%, rgba(79, 172, 254, 0.04) 0%, transparent 35%);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }

        header {
            text-align: center;
            margin-bottom: 45px;
        }

        header h1 {
            font-size: 2.8rem;
            font-weight: 800;
            background: linear-gradient(to right, #00f2fe, #4facfe);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }

        header p {
            color: var(--text-muted);
            font-size: 1.1rem;
            font-weight: 300;
        }

        .grid-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 35px;
        }

        .stat-card {
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 24px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .stat-card:hover {
            transform: translateY(-4px);
            border-color: rgba(0, 242, 254, 0.2);
            box-shadow: 0 12px 35px rgba(0, 242, 254, 0.04);
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
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 600;
            font-variant-numeric: tabular-nums;
        }

        .stat-unit {
            font-size: 0.85rem;
            color: var(--text-muted);
            font-weight: 400;
            margin-left: 3px;
        }

        .main-panel {
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            backdrop-filter: blur(20px);
            border-radius: 24px;
            padding: 35px;
            margin-bottom: 35px;
        }

        .main-panel h2 {
            font-size: 1.5rem;
            margin-bottom: 20px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .main-panel h2::before {
            content: '';
            display: inline-block;
            width: 6px; height: 22px;
            background: var(--accent-glow);
            border-radius: 3px;
        }

        .url-box {
            background: rgba(0, 0, 0, 0.35);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 16px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-family: monospace;
            font-size: 0.95rem;
            color: var(--accent-solid);
            margin-bottom: 30px;
        }

        .btn-copy {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 7px 14px;
            border-radius: 8px;
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

        .device-accordion {
            border: 1px solid var(--border-color);
            border-radius: 14px;
            overflow: hidden;
            margin-bottom: 12px;
            background: rgba(255, 255, 255, 0.01);
            transition: all 0.3s;
        }

        .device-header {
            padding: 16px 22px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
            user-select: none;
        }

        .device-header:hover {
            background: rgba(255, 255, 255, 0.03);
        }

        .device-content {
            padding: 22px;
            background: rgba(0, 0, 0, 0.18);
            border-top: 1px solid var(--border-color);
            display: none;
            line-height: 1.6;
        }

        .device-content ol {
            padding-left: 20px;
        }

        .device-content li {
            margin-bottom: 8px;
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
            padding: 9px 18px;
            border-radius: 8px;
            font-weight: 600;
            margin-top: 12px;
            transition: all 0.2s;
        }

        .btn-download:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 242, 254, 0.25);
        }

        .table-container {
            width: 100%;
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.95rem;
        }

        th {
            padding: 12px 16px;
            border-bottom: 2px solid var(--border-color);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.5px;
        }

        td {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }

        tr:hover td {
            background: rgba(255, 255, 255, 0.01);
        }

        .dns-rank-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-align: center;
        }

        .rank-primary {
            background: rgba(0, 242, 254, 0.15);
            color: var(--accent-solid);
            border: 1px solid rgba(0, 242, 254, 0.3);
        }

        .rank-secondary {
            background: rgba(0, 136, 255, 0.15);
            color: #55b2ff;
            border: 1px solid rgba(0, 136, 255, 0.3);
        }

        .rank-backup {
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-muted);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .rank-offline {
            background: rgba(255, 59, 48, 0.15);
            color: var(--color-offline);
            border: 1px solid rgba(255, 59, 48, 0.3);
        }

        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: 500;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            box-shadow: 0 0 8px currentColor;
        }

        .status-Healthy { color: var(--color-healthy); }
        .status-Warning { color: var(--color-warning); }
        .status-Offline { color: var(--color-offline); }

        .progress-bar-container {
            width: 100%;
            max-width: 150px;
            height: 8px;
            background: rgba(255, 255, 255, 0.04);
            border-radius: 4px;
            overflow: hidden;
            display: inline-block;
            vertical-align: middle;
            margin-right: 10px;
        }

        .progress-bar-fill {
            height: 100%;
            background: var(--accent-glow);
            border-radius: 4px;
            transition: width 0.5s ease;
        }

        .latency-badge {
            font-variant-numeric: tabular-nums;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }

        .latency-Healthy { color: var(--color-healthy); }
        .latency-Warning { color: var(--color-warning); }
        .latency-Offline { color: var(--color-offline); }

        .penalty-badge {
            background: rgba(255, 59, 48, 0.12);
            color: #ff453a;
            border: 1px solid rgba(255, 59, 48, 0.2);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-left: 5px;
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
            <h1>Antigravity Adaptive DNS</h1>
            <p>Hệ thống định tuyến thích ứng EMA, cân bằng tải & tối ưu hoá trễ truy vấn thực tế</p>
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
                <div class="stat-title">Độ trễ hệ thống</div>
                <div class="stat-value" id="avg-latency">0<span class="stat-unit">ms</span></div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Bộ nhớ đệm</div>
                <div class="stat-value" id="cache-size">0<span class="stat-unit">records</span></div>
            </div>
        </div>

        <div class="main-panel">
            <h2>Bảng giám sát cân bằng tải & hiệu năng thích ứng (Adaptive DNS)</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Định tuyến</th>
                            <th>DNS Server</th>
                            <th>IP</th>
                            <th>Ping Active</th>
                            <th>Trễ Thực Tế (EMA)</th>
                            <th>Mất gói / Lỗi</th>
                            <th>Trạng thái</th>
                            <th>Chia tải thực tế</th>
                        </tr>
                    </thead>
                    <tbody id="dns-table-body">
                        <!-- Rendered dynamically -->
                    </tbody>
                </table>
            </div>
        </div>

        <div class="main-panel">
            <h2>Đường dẫn DNS over HTTPS (DoH) cá nhân</h2>
            <div class="url-box">
                <span id="doh-url">https://${host}/dns-query</span>
                <button class="btn-copy" onclick="copyUrl()">Sao chép</button>
            </div>

            <h2>Cấu hình thiết bị</h2>
            <div class="setup-steps">
                <div class="device-accordion">
                    <div class="device-header" onclick="toggleAccordion(this)">
                        <span>Apple iOS / macOS (Tải profile hệ thống tự động)</span>
                        <span class="arrow"></span>
                    </div>
                    <div class="device-content">
                        <p>Nhấp vào nút bên dưới để tải và cài đặt profile hệ thống:</p>
                        <a href="/download-profile" class="btn-download">Tải Profile Cấu Hình (.mobileconfig)</a>
                        <p style="margin-top: 15px; font-size: 0.9rem; color: var(--text-muted);">
                            <strong>Tính năng bảo mật nâng cao:</strong><br>
                            • <strong>Ép buộc điều tuyến (Prohibit Fallback)</strong>: Gom và buộc 100% truy vấn DNS đi qua máy chủ DoH, ngăn chặn việc rò rỉ (leak) ra DNS mặc định của Wi-Fi hay nhà mạng di động.<br>
                            • <strong>Tối ưu chuyển mạng (Bootstrap DNS)</strong>: Khai báo sẵn các IP định danh (1.1.1.1, 8.8.8.8) giúp thiết bị iOS kết nối ngay lập tức và duy trì độ trễ cực thấp khi di chuyển giữa Wi-Fi và mạng di động 4G/5G.
                        </p>
                    </div>
                </div>

                <div class="device-accordion">
                    <div class="device-header" onclick="toggleAccordion(this)">
                        <span>Google Android (Thông qua Intra/Nebulo)</span>
                        <span class="arrow"></span>
                    </div>
                    <div class="device-content">
                        <p>Sử dụng app **Intra** hoặc **Nebulo** trên Android, thêm Custom URL và dán đường link DoH phía trên của bạn vào.</p>
                    </div>
                </div>

                <div class="device-accordion">
                    <div class="device-header" onclick="toggleAccordion(this)">
                        <span>Trình duyệt (Chrome / Firefox / Edge)</span>
                        <span class="arrow"></span>
                    </div>
                    <div class="device-content">
                        <p>Mở mục Cài đặt DNS an toàn trên trình duyệt của bạn (Chrome: Bảo mật -> Sử dụng DNS an toàn -> Tùy chỉnh; Firefox: Quyền riêng tư -> DNS qua HTTPS -> Max -> Tùy chỉnh) và dán link DoH vào.</p>
                    </div>
                </div>
            </div>
        </div>

        <footer>
            <p>Thuật toán tự thích ứng EMA & O(1) Routing. Phát triển bởi Antigravity Coding Engine v3.</p>
        </footer>
    </div>

    <script>
        function toggleAccordion(el) {
            el.parentElement.classList.toggle('active');
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
                
                document.getElementById('total-queries').innerText = data.totalQueries.toLocaleString();
                const hitRate = data.totalQueries > 0 ? Math.round((data.cacheHits / data.totalQueries) * 100) : 0;
                document.getElementById('cache-hit-rate').innerHTML = hitRate + '<span class="stat-unit">%</span>';
                document.getElementById('avg-latency').innerHTML = Math.round(data.averageLatency) + '<span class="stat-unit">ms</span>';
                document.getElementById('cache-size').innerHTML = data.cacheSize + '<span class="stat-unit">records</span>';

                const tableBody = document.getElementById('dns-table-body');
                tableBody.innerHTML = '';

                const upstreams = data.upstreams || [];
                const totalRouted = upstreams.reduce((acc, curr) => acc + curr.routedQueries, 0);

                // Sort by routing score ascending (exactly how server sorts candidates)
                const sortedUpstreams = [...upstreams].sort((a, b) => {
                    if (a.status === 'Offline') return 1;
                    if (b.status === 'Offline') return -1;
                    return a.score - b.score;
                });

                sortedUpstreams.forEach((dns, index) => {
                    let rankText = 'Backup';
                    let rankClass = 'rank-backup';
                    
                    if (dns.status === 'Offline') {
                        rankText = 'Offline';
                        rankClass = 'rank-offline';
                    } else if (index === 0) {
                        rankText = '#1 Primary';
                        rankClass = 'rank-primary';
                    } else if (index === 1) {
                        rankText = '#2 Secondary';
                        rankClass = 'rank-secondary';
                    }

                    const routedPercent = totalRouted > 0 ? Math.round((dns.routedQueries / totalRouted) * 100) : 0;
                    
                    // Latency class
                    let latClass = 'latency-Healthy';
                    if (dns.avgLatency > 250) latClass = 'latency-Offline';
                    else if (dns.avgLatency > 120) latClass = 'latency-Warning';

                    // Real latency display
                    let realLatStr = '--';
                    if (dns.realAvgLatency > 0) {
                        realLatStr = dns.realAvgLatency + ' ms';
                    }

                    // Penalty tag
                    let penaltyTag = '';
                    if (dns.penalty > 0) {
                        penaltyTag = '<span class="penalty-badge">+' + dns.penalty + 'ms Phạt</span>';
                    }

                    const row = document.createElement('tr');
                    row.innerHTML = '<td><span class="dns-rank-badge ' + rankClass + '">' + rankText + '</span></td>' +
                        '<td><strong>' + dns.name + '</strong>' + penaltyTag + '</td>' +
                        '<td style="font-family: monospace;">' + dns.ip + '</td>' +
                        '<td><span class="latency-badge ' + latClass + '">' + (dns.status === 'Offline' ? '--' : dns.avgLatency + ' ms') + '</span></td>' +
                        '<td><span class="latency-badge" style="color: #4facfe;">' + realLatStr + '</span></td>' +
                        '<td style="font-family: tabular-nums;">' + dns.lossRate + '% / ' + dns.realErrorsCount + ' lỗi</td>' +
                        '<td>' +
                            '<span class="status-indicator status-' + dns.status + '">' +
                                '<span class="status-dot" style="background-color: currentColor;"></span>' +
                                dns.status +
                            '</span>' +
                        '</td>' +
                        '<td>' +
                            '<div class="progress-bar-container">' +
                                '<div class="progress-bar-fill" style="width: ' + routedPercent + '%"></div>' +
                            '</div>' +
                            '<span style="font-size: 0.85rem; font-weight: 600;">' + dns.routedQueries + ' (' + routedPercent + '%)</span>' +
                        '</td>';
                    tableBody.appendChild(row);
                });

            } catch (err) {
                console.error('Error loading stats:', err);
            }
        }

        fetchStats();
        setInterval(fetchStats, 3000);
    </script>
</body>
</html>`;

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  }
});

server.listen(PORT, () => {
  console.log(`Antigravity Adaptive DNS Server running on http://localhost:${PORT}`);
  console.log(`DNS health-check active monitoring started.`);
});
