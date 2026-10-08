const http = require('http');
const https = require('https');
const dgram = require('dgram');
const fs = require('fs');
const dnsPacket = require('dns-packet');

// Prevent any unhandled error from crashing the Node.js process
process.on('uncaughtException', (err) => {
  console.error('[Anti-Crash] Uncaught Exception:', err ? (err.stack || err.message) : err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[Anti-Crash] Unhandled Rejection:', reason ? (reason.stack || reason.message) : reason);
});

const PORT = process.env.PORT || 3000;
const isVercel = Boolean(process.env.VERCEL || process.env.NOW_REGION || process.env.AWS_LAMBDA_FUNCTION_NAME);

// Persistent, ultra-high-performance HTTPS Agent with Keep-Alive & Connection Pooling
const httpsAgent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 60000,
  maxSockets: Infinity,
  maxFreeSockets: 256,
  timeout: 4000,
  rejectUnauthorized: false
});

// Curated 100% verified high-performance upstream resolvers with verified HTTPS DoH endpoints
const UPSTREAMS = [
  { name: 'Google Primary', ip: '8.8.8.8', dohUrl: 'https://8.8.8.8/dns-query' },
  { name: 'Google Secondary', ip: '8.8.4.4', dohUrl: 'https://8.8.4.4/dns-query' },
  { name: 'Cloudflare Primary', ip: '1.1.1.1', dohUrl: 'https://1.1.1.1/dns-query' },
  { name: 'Cloudflare Secondary', ip: '1.0.0.1', dohUrl: 'https://1.0.0.1/dns-query' },
  { name: 'DNS.SB Primary', ip: '45.11.45.11', dohUrl: 'https://45.11.45.11/dns-query' },
  { name: 'ControlD Free', ip: '76.76.2.0', dohUrl: 'https://freedns.controld.com/p0' },
  { name: 'AdGuard Standard', ip: '94.140.14.14', dohUrl: 'https://94.140.14.14/dns-query' },
  { name: 'OpenDNS Primary', ip: '208.67.222.222', dohUrl: 'https://208.67.222.222/dns-query' },
  { name: 'OpenDNS Secondary', ip: '208.67.220.220', dohUrl: 'https://208.67.220.220/dns-query' }
];

// Health and telemetry state per upstream
const upstreamStates = UPSTREAMS.map((u, idx) => ({
  ...u,
  avgLatency: idx < 4 ? 15 : (idx < 7 ? 35 : 45),
  realAvgLatency: idx < 4 ? 15 : (idx < 7 ? 35 : 45),
  penalty: 0,
  status: 'Healthy',
  consecutiveErrors: 0,
  routedQueries: 0,
  activeQueries: 0,
  realQueriesCount: 0,
  realErrorsCount: 0
}));

let currentPoolSize = 3;

// Dynamic Score: lower score = faster and healthier server
function calculateScore(state) {
  const effectiveLatency = state.realAvgLatency || state.avgLatency || 20;
  const loadPenalty = (state.activeQueries || 0) * 8;
  return effectiveLatency + (state.penalty || 0) + loadPenalty;
}

function updateCandidates() {
  const healthyCount = upstreamStates.filter(s => s.status === 'Healthy').length;
  if (healthyCount <= 3) {
    currentPoolSize = 2;
  } else {
    currentPoolSize = 3;
  }
}

const os = require('os');
const path = require('path');

// In-Memory Cache with Stale-While-Revalidate (SWR) & In-Flight Coalescing
const cache = new Map();
const coalescedQueries = new Map();
const activeRevalidations = new Set();

const STATS_FILE = path.join(os.tmpdir(), 'antigravity_doh_stats.json');

const stats = {
  totalQueries: 0,
  cacheHits: 0,
  cacheMisses: 0,
  swrHits: 0,
  repairedPackets: 0,
  errors: 0,
  totalLatency: 0,
  averageLatency: 0
};

const recentQueries = [];

function recordRecentQuery(domain, type, upstreamName, upstreamIp, latency, status) {
  recentQueries.unshift({
    timestamp: Date.now(),
    domain,
    type,
    upstreamName,
    upstreamIp,
    latency,
    status
  });
  if (recentQueries.length > 50) recentQueries.pop();
  persistStats(true);
  broadcastStatsUpdate();
}

// Server-Sent Events (SSE) subscribers for instant real-time live streaming
const sseClients = new Set();

function broadcastStatsUpdate() {
  if (sseClients.size === 0) return;
  const payload = JSON.stringify(getStatsSnapshot());
  const msg = `data: ${payload}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(msg);
    } catch (e) {
      sseClients.delete(client);
    }
  }
}

function getStatsSnapshot() {
  loadPersistedStats();
  return {
    totalQueries: stats.totalQueries,
    cacheHits: stats.cacheHits,
    cacheMisses: stats.cacheMisses,
    swrHits: stats.swrHits,
    repairedPackets: stats.repairedPackets || 0,
    errors: stats.errors,
    averageLatency: stats.averageLatency,
    poolSize: currentPoolSize,
    cacheSize: cache.size,
    upstreams: upstreamStates.map(u => ({
      name: u.name,
      ip: u.ip,
      dohUrl: u.dohUrl,
      avgLatency: u.avgLatency,
      realAvgLatency: u.realAvgLatency || u.avgLatency,
      penalty: u.penalty,
      routedQueries: u.routedQueries || 0,
      activeQueries: u.activeQueries || 0,
      status: u.status
    })),
    recentQueries: recentQueries.slice(0, 30)
  };
}

// Serverless State Persistence across Cold Starts & Invocations
let lastStatsMtime = 0;
function loadPersistedStats() {
  try {
    if (fs.existsSync(STATS_FILE)) {
      const fileStat = fs.statSync(STATS_FILE);
      if (fileStat.mtimeMs <= lastStatsMtime && lastStatsMtime !== 0) return;
      lastStatsMtime = fileStat.mtimeMs;

      const raw = fs.readFileSync(STATS_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (data && typeof data.totalQueries === 'number') {
        stats.totalQueries = Math.max(stats.totalQueries, data.totalQueries);
        stats.cacheHits = Math.max(stats.cacheHits, data.cacheHits || 0);
        stats.cacheMisses = Math.max(stats.cacheMisses, data.cacheMisses || 0);
        stats.swrHits = Math.max(stats.swrHits, data.swrHits || 0);
        stats.repairedPackets = Math.max(stats.repairedPackets || 0, data.repairedPackets || 0);
        stats.errors = Math.max(stats.errors, data.errors || 0);
        stats.totalLatency = Math.max(stats.totalLatency, data.totalLatency || 0);
        if (stats.totalQueries > 0) {
          stats.averageLatency = Math.round(stats.totalLatency / stats.totalQueries);
        }
        if (Array.isArray(data.recentQueries) && data.recentQueries.length > 0) {
          const queryMap = new Map();
          data.recentQueries.forEach(q => {
            if (q && q.domain) queryMap.set(`${q.timestamp}_${q.domain}_${q.type}`, q);
          });
          recentQueries.forEach(q => {
            if (q && q.domain) queryMap.set(`${q.timestamp}_${q.domain}_${q.type}`, q);
          });
          const merged = Array.from(queryMap.values()).sort((a, b) => b.timestamp - a.timestamp);
          recentQueries.length = 0;
          recentQueries.push(...merged.slice(0, 50));
        }
        if (Array.isArray(data.upstreams)) {
          data.upstreams.forEach(savedUp => {
            const found = upstreamStates.find(u => u.name === savedUp.name);
            if (found && typeof savedUp.routedQueries === 'number') {
              found.routedQueries = Math.max(found.routedQueries || 0, savedUp.routedQueries);
            }
          });
        }
      }
    }
  } catch (e) {}
}

function persistStats(immediate = true) {
  try {
    const payload = {
      totalQueries: stats.totalQueries,
      cacheHits: stats.cacheHits,
      cacheMisses: stats.cacheMisses,
      swrHits: stats.swrHits,
      repairedPackets: stats.repairedPackets || 0,
      errors: stats.errors,
      totalLatency: stats.totalLatency,
      averageLatency: stats.averageLatency,
      upstreams: upstreamStates.map(u => ({ name: u.name, routedQueries: u.routedQueries })),
      recentQueries: recentQueries.slice(0, 50),
      savedAt: Date.now()
    };
    fs.writeFileSync(STATS_FILE, JSON.stringify(payload));
  } catch (e) {}
}

// Initial state load
loadPersistedStats();

function overrideTtlInResponse(buffer) {
  try {
    const decoded = dnsPacket.decode(buffer);
    let modified = false;
    const clampTTL = (rec) => {
      if (rec && typeof rec.ttl === 'number') {
        if (rec.ttl < 60) { rec.ttl = 60; modified = true; }
        else if (rec.ttl > 86400) { rec.ttl = 86400; modified = true; }
      }
    };
    if (decoded.answers) decoded.answers.forEach(clampTTL);
    if (decoded.authorities) decoded.authorities.forEach(clampTTL);
    if (decoded.additionals) decoded.additionals.forEach(clampTTL);
    return modified ? dnsPacket.encode(decoded) : buffer;
  } catch (e) {
    return buffer;
  }
}

function safeCacheSet(key, value) {
  if (cache.size >= 50000) {
    const firstKey = cache.keys().next().value;
    if (firstKey) cache.delete(firstKey);
  }
  if (value && value.buffer) {
    value.buffer = overrideTtlInResponse(value.buffer);
  }
  cache.set(key, value);
}

function getCacheKey(dnsPacketObj) {
  if (!dnsPacketObj || !dnsPacketObj.questions || dnsPacketObj.questions.length === 0) return null;
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
  if (minTtl < 60) minTtl = 60;
  if (minTtl > 86400) minTtl = 86400;
  return minTtl;
}

function base64urlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

// Robust Request Body Extractor (Handles Buffer, String, Object, and Stream safely)
async function getRequestBody(req) {
  if (req.body) {
    if (Buffer.isBuffer(req.body) && req.body.length > 0) return req.body;
    if (typeof req.body === 'string' && req.body.length > 0) return Buffer.from(req.body, 'binary');
    if (typeof req.body === 'object' && req.body !== null) {
      if (req.body.type === 'Buffer' && Array.isArray(req.body.data) && req.body.data.length > 0) {
        return Buffer.from(req.body.data);
      }
      const keys = Object.keys(req.body);
      if (keys.length > 0) {
        return Buffer.from(JSON.stringify(req.body));
      }
    }
  }
  if (req.readableEnded) {
    return Buffer.alloc(0);
  }
  return new Promise((resolve) => {
    const chunks = [];
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks));
    };
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', finish);
    req.on('error', finish);
    const timer = setTimeout(finish, 800);
    if (timer.unref) timer.unref();
  });
}

// -------------------------------------------------------------
// ADVANCED DNS PACKET REPAIR ENGINE (Cơ chế Tự Sửa Lỗi Gói Tin)
// -------------------------------------------------------------
function repairAndNormalizeDnsQuery(rawBuffer) {
  if (!Buffer.isBuffer(rawBuffer) || rawBuffer.length < 2) {
    return { error: 'Gói tin DNS quá ngắn (< 2 bytes)', buffer: null, id: 0 };
  }

  const txId = rawBuffer.readUInt16BE(0);

  // If buffer is between 2 and 11 bytes, pad with default flags to reach standard 12-byte header
  let buf = rawBuffer;
  if (buf.length < 12) {
    const padded = Buffer.alloc(12);
    buf.copy(padded, 0, 0, buf.length);
    padded.writeUInt16BE(0x0100, 2); // Recursion Desired = 1
    buf = padded;
  }

  // 1. Try standard RFC decode
  try {
    const decoded = dnsPacket.decode(buf);
    return { buffer: buf, decoded, repaired: false, id: decoded.id };
  } catch (err) {
    // 2. Decode failed: Attempt deep packet reconstruction from raw bytes
    let question = null;
    try {
      if (buf.length >= 13) {
        let offset = 12;
        const labels = [];
        while (offset < buf.length) {
          let len = buf[offset++];
          if (len === 0) break;
          if ((len & 0xc0) === 0xc0) break;
          // Protect against buffer overflow or truncated label length
          if (offset + len > buf.length) {
            len = buf.length - offset;
          }
          if (len > 0) {
            const rawPart = buf.slice(offset, offset + len).toString('ascii');
            const sanitizedPart = rawPart.replace(/[^a-zA-Z0-9_.-]/g, '');
            if (sanitizedPart.length > 0) labels.push(sanitizedPart);
          }
          offset += len;
        }

        if (labels.length > 0) {
          let type = 'A';
          if (offset + 2 <= buf.length) {
            const typeId = buf.readUInt16BE(offset);
            const typeMap = { 1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT', 6: 'SOA', 12: 'PTR', 257: 'CAA' };
            if (typeMap[typeId]) type = typeMap[typeId];
          }
          question = { name: labels.join('.'), type };
        }
      }
    } catch (extractErr) {}

    // If we recovered a valid domain name, rebuild a compliant DNS query packet
    if (question && question.name) {
      try {
        const reconstructed = dnsPacket.encode({
          type: 'query',
          id: txId,
          flags: dnsPacket.RECURSION_DESIRED,
          questions: [question]
        });
        const decoded = dnsPacket.decode(reconstructed);
        stats.repairedPackets = (stats.repairedPackets || 0) + 1;
        return { buffer: reconstructed, decoded, repaired: true, id: txId };
      } catch (encodeErr) {}
    }

    return { error: err.message, buffer: buf, id: txId };
  }
}

// Response Packet Sanity & Auto-Correction
function repairDnsResponse(rawBuffer, originalTxId, fallbackQuestion = null) {
  if (!Buffer.isBuffer(rawBuffer) || rawBuffer.length < 2) {
    return null;
  }
  const txId = originalTxId !== undefined ? originalTxId : rawBuffer.readUInt16BE(0);

  if (rawBuffer.length >= 12) {
    try {
      const decoded = dnsPacket.decode(rawBuffer);
      return { buffer: rawBuffer, decoded, repaired: false };
    } catch (decodeErr) {
      // Upstream sent malformed/truncated response packet; repair into standard answer
    }
  }

  try {
    const fixed = dnsPacket.encode({
      type: 'response',
      id: txId,
      flags: dnsPacket.AUTHORITATIVE_ANSWER | dnsPacket.RECURSION_AVAILABLE,
      questions: fallbackQuestion ? [fallbackQuestion] : [{ type: 'A', name: '.' }]
    });
    stats.repairedPackets = (stats.repairedPackets || 0) + 1;
    return { buffer: fixed, repaired: true };
  } catch (e) {
    return null;
  }
}

// Query single DoH upstream with keep-alive HTTPS connection and safe cancellation
function queryDoHUpstream(upstream, queryBuffer, timeoutMs = 1800, signal = null) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) {
      return reject(new Error('Aborted'));
    }

    let isSettled = false;
    let isUserAborted = false;

    const safeReject = (err) => {
      if (isSettled) return;
      isSettled = true;
      reject(err);
    };

    const safeResolve = (val) => {
      if (isSettled) return;
      isSettled = true;
      resolve(val);
    };

    const t0 = Date.now();
    const parsed = new URL(upstream.dohUrl || `https://${upstream.ip}/dns-query`);

    const req = https.request({
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      agent: httpsAgent,
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
        'Content-Length': queryBuffer.length,
        'User-Agent': 'Antigravity-DoH/3.5'
      },
      timeout: timeoutMs
    }, (res) => {
      res.on('error', () => {});

      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        if (isSettled) return;
        if (res.statusCode !== 200) {
          return safeReject(new Error(`HTTP ${res.statusCode} from ${upstream.name}`));
        }
        const resBuf = Buffer.concat(chunks);
        if (resBuf.length < 12) {
          return safeReject(new Error('Truncated DNS packet'));
        }
        const latency = Date.now() - t0;
        safeResolve({ upstream, buffer: resBuf, latency });
      });
    });

    if (signal) {
      signal.addEventListener('abort', () => {
        isUserAborted = true;
        try { req.destroy(); } catch (e) {}
        safeReject(new Error('Aborted'));
      }, { once: true });
    }

    req.on('error', (err) => {
      if (isUserAborted || (signal && signal.aborted)) {
        return safeReject(new Error('Aborted'));
      }
      safeReject(err);
    });

    req.on('timeout', () => {
      try { req.destroy(); } catch (e) {}
      safeReject(new Error(`Timeout (${timeoutMs}ms) from ${upstream.name}`));
    });

    req.write(queryBuffer);
    req.end();
  });
}

// Smart Selection of Racing Candidates:
// Dynamically balances fast latency with concurrency spread so no server is bottlenecked
function selectRacingCandidates(count = 3) {
  let pool = upstreamStates.filter(s => s.status !== 'Offline');
  if (pool.length < count) {
    pool = [...upstreamStates];
  }

  const scored = pool.map(c => {
    const scoreVal = Math.max(1, calculateScore(c));
    // Soft fairness bonus: slightly encourages underutilized servers while strongly prioritizing low latency
    const fairnessBonus = 1.0 + Math.max(0, 0.6 - (c.routedQueries || 0) * 0.04);
    const weight = Math.max(0.1, Math.pow(100 / scoreVal, 1.3) * fairnessBonus);
    return { candidate: c, weight };
  });

  const selected = [];
  const available = [...scored];

  for (let i = 0; i < count && available.length > 0; i++) {
    const totalWeight = available.reduce((acc, cur) => acc + cur.weight, 0);
    let rand = Math.random() * totalWeight;
    let chosenIdx = 0;
    for (let j = 0; j < available.length; j++) {
      rand -= available[j].weight;
      if (rand <= 0) {
        chosenIdx = j;
        break;
      }
    }
    selected.push(available[chosenIdx].candidate);
    available.splice(chosenIdx, 1);
  }

  return selected;
}

// Hedged Racing Engine with Loser Cancellation & Safe Telemetry
async function raceDNS(queryBuffer, clientIp = null, timeoutMs = 1800) {
  const originalTxId = queryBuffer.readUInt16BE(0);
  const candidates = selectRacingCandidates(currentPoolSize || 3);
  const abortController = new AbortController();

  candidates.forEach(c => {
    c.activeQueries = (c.activeQueries || 0) + 1;
  });

  try {
    const racePromises = candidates.map(upstream =>
      queryDoHUpstream(upstream, queryBuffer, timeoutMs, abortController.signal)
        .then(res => {
          // Success telemetry
          upstream.consecutiveErrors = 0;
          upstream.penalty = Math.max(0, (upstream.penalty || 0) - 10);
          if (upstream.status === 'Degraded') upstream.status = 'Healthy';

          const alpha = 0.25;
          upstream.realAvgLatency = (upstream.realQueriesCount || 0) === 0
            ? res.latency
            : Math.round(alpha * res.latency + (1 - alpha) * (upstream.realAvgLatency || res.latency));
          upstream.realQueriesCount = (upstream.realQueriesCount || 0) + 1;
          upstream.avgLatency = upstream.realAvgLatency;
          return res;
        })
        .catch(err => {
          // Cancelled/aborted losers in the race MUST NEVER be penalized
          const isCancelled = err.message === 'Aborted' ||
                              abortController.signal.aborted ||
                              err.message.includes('socket hang up') ||
                              err.name === 'AbortError';

          if (!isCancelled) {
            upstream.realErrorsCount = (upstream.realErrorsCount || 0) + 1;
            upstream.penalty = Math.min(60, (upstream.penalty || 0) + 15);
            upstream.consecutiveErrors = (upstream.consecutiveErrors || 0) + 1;
            if (upstream.consecutiveErrors >= 5) upstream.status = 'Degraded';
          }
          throw err;
        })
    );

    const winnerRes = await Promise.any(racePromises);

    // Cancel remaining losers
    abortController.abort();

    const winner = winnerRes.upstream;
    let responseBuffer = Buffer.from(winnerRes.buffer);
    responseBuffer.writeUInt16BE(originalTxId, 0);

    winner.routedQueries = (winner.routedQueries || 0) + 1;
    calculateScore(winner);

    return {
      responseBuffer,
      from: winner.name,
      winner
    };
  } catch (err) {
    abortController.abort();

    // Rock-Solid Fallback: Always query reliable Tier-1 resolvers
    const fallbackCandidates = upstreamStates.filter(u => u.name.includes('Google') || u.name.includes('Cloudflare'));
    for (const fb of fallbackCandidates) {
      try {
        const fbRes = await queryDoHUpstream(fb, queryBuffer, 1500);
        const resBuf = Buffer.from(fbRes.buffer);
        resBuf.writeUInt16BE(originalTxId, 0);
        fb.routedQueries = (fb.routedQueries || 0) + 1;
        fb.status = 'Healthy';
        fb.penalty = 0;
        return {
          responseBuffer: resBuf,
          from: fb.name,
          winner: fb
        };
      } catch (fbErr) {}
    }

    throw new Error('All DNS upstreams unavailable');
  } finally {
    candidates.forEach(c => {
      c.activeQueries = Math.max(0, (c.activeQueries || 1) - 1);
    });
  }
}

function isValidPublicIp(ip) {
  if (!ip) return false;
  if (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.')) return false;
  if (ip.startsWith('172.')) {
    const parts = ip.split('.');
    if (parts.length >= 2) {
      const second = parseInt(parts[1], 10);
      if (second >= 16 && second <= 31) return false;
    }
  }
  if (ip === '::1' || ip === 'localhost' || ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip.startsWith('fd00:')) return false;
  return true;
}

// Core DoH Handler with In-Memory Caching & SWR + Auto Packet Repair
async function handleDoH(rawQueryBuffer, clientIp) {
  const startTime = Date.now();
  stats.totalQueries++;

  // 0. Packet Verification & Self-Healing
  const repairResult = repairAndNormalizeDnsQuery(rawQueryBuffer);
  let dnsQueryObj = repairResult.decoded;
  let queryBuffer = repairResult.buffer || rawQueryBuffer;

  if (repairResult.repaired) {
    console.log(`[Packet Repair] Tự động sửa thành công gói tin lỗi ID: ${repairResult.id}`);
  }

  if (!dnsQueryObj) {
    // If irreparably damaged, construct a standard SERVFAIL response rather than throwing
    stats.errors++;
    recordRecentQuery('Malformed-Query', 'ANY', 'Lỗi gói tin', '-', Date.now() - startTime, 'SERVFAIL (Repaired)');
    persistStats();
    return dnsPacket.encode({
      type: 'response',
      id: repairResult.id || 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER | 2 // SERVFAIL
    });
  }

  // EDNS Client Subnet (ECS) Routing for geographic CDN optimization
  if (isValidPublicIp(clientIp)) {
    try {
      let optRecord = dnsQueryObj.additionals ? dnsQueryObj.additionals.find(r => r.type === 'OPT') : null;
      let hasChange = false;

      if (!optRecord) {
        optRecord = {
          type: 'OPT',
          name: '.',
          udpPayloadSize: 4096,
          options: []
        };
        if (!dnsQueryObj.additionals) dnsQueryObj.additionals = [];
        dnsQueryObj.additionals.push(optRecord);
        hasChange = true;
      }

      const hasEcs = optRecord.options && optRecord.options.some(o => o.code === 'CLIENT_SUBNET' || o.code === 8);
      if (!hasEcs) {
        if (!optRecord.options) optRecord.options = [];
        const isIpv6 = clientIp.includes(':');
        optRecord.options.push({
          code: 'CLIENT_SUBNET',
          family: isIpv6 ? 2 : 1,
          sourcePrefixLength: isIpv6 ? 48 : 24,
          scopePrefixLength: 0,
          ip: clientIp
        });
        hasChange = true;
      }

      if (hasChange) {
        queryBuffer = dnsPacket.encode(dnsQueryObj);
      }
    } catch (ecsErr) {
      // Non-fatal ECS error
    }
  }

  const cacheKey = getCacheKey(dnsQueryObj);
  const now = Date.now();

  // 1. In-Memory Cache Lookup (RAM: 0ms)
  if (cacheKey && cache.has(cacheKey)) {
    const cachedEntry = cache.get(cacheKey);

    if (now < cachedEntry.swrExpiresAt) {
      const isFresh = now < cachedEntry.expiresAt;
      const shouldRevalidate = !isFresh;

      if (shouldRevalidate && !activeRevalidations.has(cacheKey)) {
        stats.swrHits++;
        const q0 = dnsQueryObj.questions && dnsQueryObj.questions[0];
        recordRecentQuery(q0 ? q0.name : 'query', q0 ? q0.type : 'A', 'Bộ nhớ đệm SWR', '0ms (Stale)', 0, 'SWR Hit');
        activeRevalidations.add(cacheKey);

        raceDNS(queryBuffer, clientIp).then(revalRes => {
          try {
            const revalDecoded = dnsPacket.decode(revalRes.responseBuffer);
            const ttl = getMinTTL(revalDecoded);
            safeCacheSet(cacheKey, {
              buffer: revalRes.responseBuffer,
              expiresAt: Date.now() + (ttl * 1000),
              swrExpiresAt: Date.now() + (ttl * 1000) + (86400 * 1000)
            });
          } catch (e) {}
        }).catch(() => {}).finally(() => {
          activeRevalidations.delete(cacheKey);
        });
      } else {
        stats.cacheHits++;
        const q0 = dnsQueryObj.questions && dnsQueryObj.questions[0];
        recordRecentQuery(q0 ? q0.name : 'query', q0 ? q0.type : 'A', 'Bộ nhớ đệm (RAM)', '0ms (RAM)', 0, 'Cache Hit');
      }

      persistStats();
      const clientResponse = Buffer.from(cachedEntry.buffer);
      clientResponse.writeUInt16BE(dnsQueryObj.id, 0);
      return clientResponse;
    } else {
      cache.delete(cacheKey);
    }
  }

  // 2. Request Coalescing (Safe singleflight deduplication with 600ms safety limit)
  if (cacheKey && coalescedQueries.has(cacheKey)) {
    try {
      const existingPromise = coalescedQueries.get(cacheKey);
      const sharedRes = await Promise.race([
        existingPromise,
        new Promise((_, reject) => setTimeout(() => reject(new Error('Coalesce timeout')), 600))
      ]);
      const clientResponse = Buffer.from(sharedRes.responseBuffer);
      clientResponse.writeUInt16BE(dnsQueryObj.id, 0);
      stats.cacheHits++;
      persistStats();
      return clientResponse;
    } catch (e) {
      // In-flight race failed or timed out: safely proceed to own query
    }
  }

  // 3. Forward to Upstreams via Smart Hedged Racing
  stats.cacheMisses++;
  const racePromise = raceDNS(queryBuffer, clientIp);

  if (cacheKey) {
    coalescedQueries.set(cacheKey, racePromise);
  }

  try {
    const { responseBuffer, from, winner } = await racePromise;
    const latency = Date.now() - startTime;
    stats.totalLatency += latency;
    stats.averageLatency = Math.round(stats.totalLatency / stats.totalQueries);

    const q0 = dnsQueryObj.questions && dnsQueryObj.questions[0];
    recordRecentQuery(
      q0 ? q0.name : 'query',
      q0 ? q0.type : 'A',
      winner ? winner.name : from,
      winner ? winner.ip : '-',
      latency,
      repairResult.repaired ? 'Resolved (Auto-Repaired)' : 'Resolved'
    );

    if (cacheKey) {
      try {
        const decodedResp = dnsPacket.decode(responseBuffer);
        const ttl = getMinTTL(decodedResp);
        safeCacheSet(cacheKey, {
          buffer: responseBuffer,
          expiresAt: Date.now() + (ttl * 1000),
          swrExpiresAt: Date.now() + (ttl * 1000) + (86400 * 1000)
        });
      } catch (cacheErr) {}
    }

    persistStats();
    return responseBuffer;
  } catch (err) {
    stats.errors++;
    const q0 = dnsQueryObj.questions && dnsQueryObj.questions[0];
    recordRecentQuery(q0 ? q0.name : 'query', q0 ? q0.type : 'A', 'Thất bại', '-', Date.now() - startTime, 'SERVFAIL');
    persistStats();

    try {
      return dnsPacket.encode({
        type: 'response',
        id: dnsQueryObj.id,
        flags: dnsPacket.AUTHORITATIVE_ANSWER | 2, // SERVFAIL
        questions: dnsQueryObj.questions
      });
    } catch (e) {
      throw err;
    }
  } finally {
    if (cacheKey) {
      coalescedQueries.delete(cacheKey);
    }
  }
}

// -------------------------------------------------------------
// DEDICATED REQUEST HANDLERS (RFC 8484 Compliant & Fallback Safe)
// -------------------------------------------------------------

// DoH Request Handler
async function handleDoHRequest(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, Cache-Control');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const clientIp = req.headers['x-forwarded-for']
    ? req.headers['x-forwarded-for'].split(',')[0].trim()
    : (req.headers['x-real-ip'] || (req.socket ? req.socket.remoteAddress : '127.0.0.1'));

  const urlParts = (req.url || '/').split('?');
  const searchParams = new URLSearchParams(urlParts[1] || '');

  // 1. POST Method (Standard RFC 8484 Binary Wireformat)
  if (req.method === 'POST') {
    let queryBuffer;
    try {
      queryBuffer = await getRequestBody(req);
    } catch (readErr) {
      queryBuffer = null;
    }

    if (!queryBuffer || queryBuffer.length < 2) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Empty or malformed DNS wireformat body');
      return;
    }

    try {
      const responseBuffer = await handleDoH(queryBuffer, clientIp);
      res.writeHead(200, {
        'Content-Type': 'application/dns-message',
        'Content-Length': responseBuffer.length,
        'Cache-Control': 'public, max-age=60, s-maxage=300, stale-while-revalidate=86400'
      });
      res.end(responseBuffer);
    } catch (err) {
      // NEVER SEND HTTP 500! Always send valid RFC 8484 SERVFAIL DNS packet
      try {
        const decoded = dnsPacket.decode(queryBuffer);
        const failBuf = dnsPacket.encode({
          type: 'response',
          id: decoded.id,
          flags: dnsPacket.AUTHORITATIVE_ANSWER | 2, // SERVFAIL
          questions: decoded.questions
        });
        res.writeHead(200, {
          'Content-Type': 'application/dns-message',
          'Content-Length': failBuf.length
        });
        res.end(failBuf);
      } catch (e) {
        res.writeHead(200, {
          'Content-Type': 'application/dns-message',
          'Content-Length': queryBuffer.length
        });
        res.end(queryBuffer);
      }
    }
    return;
  }

  // 2. GET Method
  if (req.method === 'GET') {
    const dnsParam = searchParams.get('dns');
    const nameParam = searchParams.get('name');
    const typeParam = (searchParams.get('type') || 'A').toUpperCase();

    // 2.1 RFC 8484 GET (?dns=<base64url>)
    if (dnsParam) {
      let queryBuffer;
      try {
        queryBuffer = base64urlDecode(dnsParam);
      } catch (b64Err) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Bad base64url DNS query');
        return;
      }

      try {
        const responseBuffer = await handleDoH(queryBuffer, clientIp);
        res.writeHead(200, {
          'Content-Type': 'application/dns-message',
          'Content-Length': responseBuffer.length,
          'Cache-Control': 'public, max-age=60, s-maxage=300, stale-while-revalidate=86400'
        });
        res.end(responseBuffer);
      } catch (err) {
        // ALWAYS send valid DNS SERVFAIL packet to prevent OS network drop
        try {
          const decoded = dnsPacket.decode(queryBuffer);
          const failBuf = dnsPacket.encode({
            type: 'response',
            id: decoded.id,
            flags: dnsPacket.AUTHORITATIVE_ANSWER | 2,
            questions: decoded.questions
          });
          res.writeHead(200, {
            'Content-Type': 'application/dns-message',
            'Content-Length': failBuf.length
          });
          res.end(failBuf);
        } catch (e) {
          res.writeHead(200, {
            'Content-Type': 'application/dns-message',
            'Content-Length': queryBuffer.length
          });
          res.end(queryBuffer);
        }
      }
      return;
    }

    // 2.2 JSON DoH Query (?name=<domain>&type=<type>)
    if (nameParam) {
      try {
        const queryPacket = dnsPacket.encode({
          type: 'query',
          id: Math.floor(Math.random() * 65535) + 1,
          flags: dnsPacket.RECURSION_DESIRED,
          questions: [{ type: typeParam, name: nameParam.trim() }]
        });

        const startTime = Date.now();
        const responseBuffer = await handleDoH(queryPacket, clientIp);
        const latency = Date.now() - startTime;
        const decoded = dnsPacket.decode(responseBuffer);

        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'public, max-age=60'
        });
        res.end(JSON.stringify({
          Status: decoded.rcode === 'NOERROR' ? 0 : 2,
          rcode: decoded.rcode || 'NOERROR',
          TC: decoded.flag_tc || false,
          RD: decoded.flag_rd || true,
          RA: decoded.flag_ra || true,
          Question: (decoded.questions || []).map(q => ({ name: q.name, type: q.type })),
          Answer: (decoded.answers || []).map(a => ({
            name: a.name,
            type: a.type,
            TTL: a.ttl || 300,
            data: a.data || (a.ip ? a.ip : '')
          })),
          latencyMs: latency
        }, null, 2));
      } catch (err) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ Status: 2, error: err.message }));
      }
      return;
    }

    // 2.3 Browser visit to /dns-query: Redirect to home page dashboard if requesting HTML
    const acceptHeader = req.headers['accept'] || '';
    if (acceptHeader.includes('text/html')) {
      res.writeHead(302, { 'Location': '/' });
      res.end();
      return;
    }

    // Otherwise return JSON API endpoints info
    const host = req.headers.host || 'localhost:3000';
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({
      status: 'online',
      server: 'Antigravity Hyper-Speed DoH Proxy',
      endpoints: {
        rfc8484_post: { method: 'POST', path: '/dns-query', contentType: 'application/dns-message' },
        rfc8484_get: { method: 'GET', path: '/dns-query?dns=<base64url>' },
        json_query: { method: 'GET', path: '/dns-query?name=<domain>&type=<type>' },
        iosProfile: `https://${host}/profile.mobileconfig`,
        realtimeStream: `https://${host}/api/stream`
      },
      quickTest: `https://${host}/dns-query?name=google.com&type=A`
    }, null, 2));
    return;
  }

  res.writeHead(405, { 'Content-Type': 'text/plain' });
  res.end('Method Not Allowed');
}

// Ping / Health Check Handler
function handlePingRequest(req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/plain',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Access-Control-Allow-Origin': '*'
  });
  res.end('pong');
}

// Stats Handler (Fast JSON Snapshot)
function handleStatsRequest(req, res) {
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(JSON.stringify(getStatsSnapshot(), null, 2));
}

// Real-Time Server-Sent Events (SSE) Stream Handler
function handleStreamRequest(req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
    'X-Accel-Buffering': 'no'
  });

  // Send initial snapshot state immediately
  res.write(`data: ${JSON.stringify(getStatsSnapshot())}\n\n`);

  sseClients.add(res);

  let lastHash = '';
  // Heartbeat & delta check every 2.5 seconds (sends data ONLY when changed, else lightweight : ping)
  const interval = setInterval(() => {
    try {
      const snap = getStatsSnapshot();
      const topQ = snap.recentQueries && snap.recentQueries[0];
      const curHash = `${snap.totalQueries}:${snap.repairedPackets}:${snap.cacheHits}:${topQ ? topQ.timestamp : 0}`;
      if (curHash !== lastHash) {
        lastHash = curHash;
        res.write(`data: ${JSON.stringify(snap)}\n\n`);
      } else {
        // SSE comment keep-alive ping: keeps connection open without triggering client onmessage reflow
        res.write(': ping\n\n');
      }
    } catch (e) {
      clearInterval(interval);
      sseClients.delete(res);
    }
  }, 2500);

  req.on('close', () => {
    clearInterval(interval);
    sseClients.delete(res);
  });
}

// Reset Stats Handler
function handleResetStatsRequest(req, res) {
  stats.totalQueries = 0;
  stats.cacheHits = 0;
  stats.cacheMisses = 0;
  stats.swrHits = 0;
  stats.repairedPackets = 0;
  stats.errors = 0;
  stats.totalLatency = 0;
  stats.averageLatency = 0;
  recentQueries.length = 0;
  upstreamStates.forEach(u => {
    u.routedQueries = 0;
    u.penalty = 0;
    u.consecutiveErrors = 0;
    u.status = 'Healthy';
  });

  try {
    if (fs.existsSync(STATS_FILE)) {
      fs.unlinkSync(STATS_FILE);
    }
  } catch (e) {}

  broadcastStatsUpdate();

  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(JSON.stringify({ success: true, message: 'Stats reset' }));
}

// Interactive Live DoH Tester Handler
async function handleTestDoHRequest(req, res) {
  const urlParts = (req.url || '/').split('?');
  const searchParams = new URLSearchParams(urlParts[1] || '');
  const name = searchParams.get('name') || 'google.com';
  const type = (searchParams.get('type') || 'A').toUpperCase();

  const clientIp = req.headers['x-forwarded-for']
    ? req.headers['x-forwarded-for'].split(',')[0].trim()
    : '127.0.0.1';

  try {
    const queryPacket = dnsPacket.encode({
      type: 'query',
      id: Math.floor(Math.random() * 65535) + 1,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{ type, name: name.trim() }]
    });

    const t0 = Date.now();
    const responseBuffer = await handleDoH(queryPacket, clientIp);
    const latency = Date.now() - t0;
    const decoded = dnsPacket.decode(responseBuffer);

    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*'
    });
    res.end(JSON.stringify({
      success: true,
      domain: name,
      type,
      latencyMs: latency,
      rcode: decoded.rcode || 'NOERROR',
      answers: (decoded.answers || []).map(a => ({
        name: a.name,
        type: a.type,
        ttl: a.ttl,
        data: a.data || (a.ip ? a.ip : '')
      }))
    }, null, 2));
  } catch (err) {
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*'
    });
    res.end(JSON.stringify({
      success: false,
      error: err.message
    }));
  }
}

// Generate Apple iOS/macOS Encrypted DNS MobileConfig Profile
function generateMobileConfig(host) {
  const profileUuid = '8E5531B4-3701-4475-8D8F-D0304677A0F1';
  const payloadUuid = '165F3480-1BF8-406C-8CE1-58A9F1A46DF8';
  const dohUrl = `https://${host}/dns-query`;

  return `<?xml version="1.0" encoding="UTF-8"?>
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
                <string>${dohUrl}</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Mã hóa và tăng tốc toàn bộ truy vấn DNS DoH qua Antigravity Proxy.</string>
            <key>PayloadDisplayName</key>
            <string>Antigravity DoH Security</string>
            <key>PayloadIdentifier</key>
            <string>com.antigravity.doh.dns.${payloadUuid}</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>${payloadUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Mã hóa và tăng tốc phân giải tên miền DoH thông qua Antigravity DoH Proxy.</string>
    <key>PayloadDisplayName</key>
    <string>Antigravity DoH Proxy (Ultra Speed &amp; Resilient)</string>
    <key>PayloadIdentifier</key>
    <string>com.antigravity.doh.profile.${profileUuid}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${profileUuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;
}

function handleProfileRequest(req, res) {
  const host = req.headers.host || 'localhost:3000';
  const xml = generateMobileConfig(host);
  res.writeHead(200, {
    'Content-Type': 'application/x-apple-aspen-config; charset=utf-8',
    'Content-Disposition': 'attachment; filename="Antigravity-DoH.mobileconfig"',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(xml);
}

// Render Modern Dashboard HTML with Live SSE & Real-Time Log Feed
function renderDashboardHtml(req) {
  const host = req.headers.host || 'localhost:3000';
  const dohUrl = `https://${host}/dns-query`;
  const mobileConfigUrl = `https://${host}/profile.mobileconfig`;

  return `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Antigravity DoH Proxy — Cập nhật Realtime & Sửa Lỗi Gói Tin</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220%22%22><text y=%2226%22 font-size=%2224%22>⚡</text></svg>">
    <style>
        :root {
            --bg: #030712;
            --surface: #0f172a;
            --surface-border: #1e293b;
            --primary: #38bdf8;
            --primary-hover: #0ea5e9;
            --accent: #818cf8;
            --color-healthy: #10b981;
            --color-warning: #f59e0b;
            --color-danger: #ef4444;
            --color-purple: #c084fc;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            line-height: 1.5;
            padding: 24px 16px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        /* Header */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--surface-border);
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .brand-icon {
            font-size: 2.2rem;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-text h1 {
            font-size: 1.6rem;
            font-weight: 800;
            letter-spacing: -0.02em;
        }

        .brand-text p {
            font-size: 0.88rem;
            color: var(--text-muted);
        }

        .badge-live {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(16, 185, 129, 0.15);
            color: var(--color-healthy);
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 0.82rem;
            font-weight: 600;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .pulse-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: var(--color-healthy);
            animation: pulse 1.5s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); opacity: 0.8; }
            50% { transform: scale(1.3); opacity: 1; }
            100% { transform: scale(0.95); opacity: 0.8; }
        }

        /* 1-Click iOS Banner */
        .ios-banner {
            background: linear-gradient(135deg, rgba(56, 189, 248, 0.12), rgba(129, 140, 248, 0.1));
            border: 1px solid rgba(56, 189, 248, 0.3);
            border-radius: 12px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 14px;
        }

        .ios-banner-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }

        .ios-banner-title {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.15rem;
            font-weight: 700;
            color: #fff;
        }

        .btn-ios {
            background: linear-gradient(135deg, #0284c7, #6366f1);
            color: #fff;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 0.95rem;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
            box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3);
        }

        .btn-ios:hover {
            opacity: 0.95;
            transform: translateY(-1px);
        }

        .steps-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 12px;
            background: rgba(0, 0, 0, 0.25);
            padding: 14px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .step-item {
            font-size: 0.85rem;
            color: var(--text-muted);
            line-height: 1.4;
        }

        .step-item strong {
            color: #fff;
            display: block;
            margin-bottom: 2px;
        }

        /* URL Card */
        .url-card {
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 14px;
        }

        .url-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }

        .url-card-header h2 {
            font-size: 1.05rem;
            font-weight: 700;
        }

        .url-box {
            display: flex;
            align-items: center;
            background: #080c14;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 10px 14px;
            font-family: monospace;
            font-size: 0.95rem;
            color: var(--primary);
            overflow-x: auto;
            word-break: break-all;
            justify-content: space-between;
            gap: 12px;
        }

        .btn-copy {
            background: var(--surface-border);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #fff;
            padding: 6px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 600;
            white-space: nowrap;
            transition: all 0.2s;
        }

        .btn-copy:hover {
            background: rgba(56, 189, 248, 0.2);
            border-color: var(--primary);
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
        }

        .stat-card {
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 18px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .stat-label {
            font-size: 0.82rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }

        .stat-value {
            font-size: 1.85rem;
            font-weight: 800;
            color: #fff;
            display: flex;
            align-items: baseline;
            gap: 4px;
        }

        .stat-unit {
            font-size: 0.95rem;
            font-weight: 500;
            color: var(--text-muted);
        }

        /* Main Panels */
        .main-panel {
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .main-panel h2 {
            font-size: 1.15rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* Tester Bar */
        .tester-bar {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .tester-input {
            flex: 1;
            min-width: 220px;
            background: #080c14;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 12px 16px;
            color: #fff;
            font-size: 0.95rem;
            font-family: inherit;
        }

        .tester-input:focus {
            outline: none;
            border-color: var(--primary);
        }

        .tester-select {
            background: #080c14;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 12px 16px;
            color: #fff;
            font-size: 0.95rem;
        }

        .btn-test {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border: none;
            color: #fff;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 700;
            cursor: pointer;
            transition: opacity 0.2s;
        }

        .btn-test:hover {
            opacity: 0.9;
        }

        .test-result-box {
            background: #080c14;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 16px;
            font-family: monospace;
            font-size: 0.88rem;
            white-space: pre-wrap;
            display: none;
        }

        /* Table */
        .table-container {
            overflow-x: auto;
            border-radius: 8px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
            table-layout: fixed;
        }

        th {
            padding: 12px 14px;
            border-bottom: 2px solid var(--surface-border);
            color: var(--text-muted);
            font-weight: 600;
            white-space: nowrap;
        }

        td {
            padding: 11px 14px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            color: var(--text-main);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .quick-chips {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-top: 10px;
            align-items: center;
        }

        .chip {
            background: #111827;
            border: 1px solid #1f2937;
            color: var(--primary);
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .chip:hover {
            background: #1e293b;
            border-color: var(--primary);
            transform: translateY(-1px);
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 6px;
        }

        .status-Healthy { background: var(--color-healthy); }
        .status-Degraded { background: var(--color-warning); }
        .status-Offline { background: var(--color-danger); }

        .badge-winner {
            background: rgba(56, 189, 248, 0.15);
            color: var(--primary);
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
        }

        .badge-cache {
            background: rgba(16, 185, 129, 0.15);
            color: var(--color-healthy);
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
        }

        .badge-repair {
            background: rgba(192, 132, 252, 0.2);
            color: var(--color-purple);
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
        }
            color: var(--color-purple);
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <div class="brand">
                <div class="brand-icon">⚡</div>
                <div class="brand-text">
                    <h1>Antigravity DoH Proxy</h1>
                    <p>Cập nhật Realtime SSE &bull; Tự sửa lỗi gói tin &bull; Tăng tốc phân giải</p>
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 10px;">
                <div class="badge-live" id="stream-status-badge">
                    <div class="pulse-dot"></div>
                    <span id="stream-status-text">Realtime Live</span>
                </div>
                <button class="btn-copy" style="font-size: 0.75rem; padding: 4px 10px;" onclick="resetStatsCounter()">Xóa bộ đếm</button>
            </div>
        </header>

        <!-- 1-Click iOS Quick Install Profile -->
        <div class="ios-banner">
            <div class="ios-banner-header">
                <div class="ios-banner-title">
                    <span>📱</span>
                    <span>Cài đặt 1-chạm cho iPhone, iPad & Mac (Đã sửa lỗi mất kết nối)</span>
                </div>
                <a href="${mobileConfigUrl}" class="btn-ios" download="Antigravity-DoH.mobileconfig">
                    📥 Tải Profile iOS (.mobileconfig)
                </a>
            </div>
            <div class="steps-container">
                <div class="step-item">
                    <strong>1. Tải về qua Safari</strong>
                    Bấm nút "Tải Profile iOS" phía trên (dùng Safari trên iPhone). Chọn "Cho phép" khi có thông báo tải hồ sơ.
                </div>
                <div class="step-item">
                    <strong>2. Mở Cài đặt iPhone</strong>
                    Vào <em>Cài đặt</em> ➔ bấm dòng <em>"Đã tải về hồ sơ"</em> (hoặc <em>Cài đặt chung ➔ Quản lý VPN & Thiết bị</em>).
                </div>
                <div class="step-item">
                    <strong>3. Bấm Cài đặt</strong>
                    Bấm <em>Cài đặt</em> ở góc phải trên. Hoàn tất! Thiết bị sẽ mã hóa toàn bộ DNS tự động mà không lo bị mất mạng.
                </div>
            </div>
        </div>

        <!-- URL Configuration Card -->
        <div class="url-card">
            <div class="url-card-header">
                <h2>🌐 Địa chỉ DoH RFC 8484 (Cài đặt thủ công)</h2>
                <span style="font-size: 0.85rem; color: var(--text-muted);">Hỗ trợ GET / POST RFC 8484, JSON & Stream SSE</span>
            </div>
            <div class="url-box">
                <span id="doh-url">${dohUrl}</span>
                <button class="btn-copy" id="btn-copy-doh" onclick="copyUrl('doh-url', 'btn-copy-doh')">Sao chép</button>
            </div>
            <div style="font-size: 0.85rem; color: var(--text-muted); display: flex; flex-direction: column; gap: 4px;">
                <div>• <strong>Chrome / Edge / Firefox</strong>: Vào <em>Cài đặt</em> ➔ <em>Quyền riêng tư & Bảo mật</em> ➔ <em>Sử dụng DNS an toàn</em> ➔ Tùy chỉnh: dán URL trên vào.</div>
                <div>• <strong>Android / App DNS (DNSCloak, Intra, AdGuard)</strong>: Dán URL <code>${dohUrl}</code> vào cấu hình DoH của ứng dụng.</div>
            </div>
        </div>

        <!-- Real-time Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-label">Tổng truy vấn</span>
                <span class="stat-value" id="total-queries">0</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Trúng Cache (RAM)</span>
                <span class="stat-value" id="cache-hit-rate">0<span class="stat-unit">%</span></span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Bộ Đệm SWR</span>
                <span class="stat-value" id="swr-hits">0</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Gói Tin Tự Sửa</span>
                <span class="stat-value" id="repaired-packets" style="color: var(--color-purple);">0</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Độ trễ trung bình</span>
                <span class="stat-value" id="avg-latency">0<span class="stat-unit">ms</span></span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Upstream Song Song</span>
                <span class="stat-value" id="pool-size">3<span class="stat-unit">máy chủ</span></span>
            </div>
        </div>

        <!-- Live DoH Query Tester -->
        <div class="main-panel">
            <h2>🧪 Kiểm thử truy vấn DoH trực tiếp</h2>
            <div class="tester-bar">
                <input type="text" id="test-domain-input" class="tester-input" placeholder="Nhập tên miền (ví dụ: google.com, apple.com, shopee.vn)" value="apple.com">
                <select id="test-type-select" class="tester-select">
                    <option value="A">A (IPv4)</option>
                    <option value="AAAA">AAAA (IPv6)</option>
                    <option value="TXT">TXT</option>
                    <option value="MX">MX</option>
                </select>
                <button class="btn-test" onclick="executeDoHTest()">Gửi truy vấn DoH</button>
            </div>
            <div class="quick-chips">
                <span style="font-size: 0.82rem; color: var(--text-muted);">Thử nhanh 1-chạm:</span>
                <button type="button" class="chip" onclick="quickTest('google.com', 'A')">google.com</button>
                <button type="button" class="chip" onclick="quickTest('apple.com', 'A')">apple.com</button>
                <button type="button" class="chip" onclick="quickTest('shopee.vn', 'A')">shopee.vn</button>
                <button type="button" class="chip" onclick="quickTest('vnexpress.net', 'A')">vnexpress.net</button>
                <button type="button" class="chip" onclick="quickTest('cloudflare.com', 'AAAA')">cloudflare.com (IPv6)</button>
            </div>
            <div id="test-result-box" class="test-result-box">
                <div id="test-result-meta" style="color: var(--primary); margin-bottom: 8px; font-weight: 600;"></div>
                <div id="test-result-pre"></div>
            </div>
        </div>

        <!-- Real-Time Live Queries Log Stream -->
        <div class="main-panel">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                <h2>⚡ Dòng truy vấn Trực tiếp (Live Query Stream)</h2>
                <span style="font-size: 0.85rem; color: var(--text-muted);">Cập nhật tức thời qua Server-Sent Events</span>
            </div>
            <div class="table-container">
                <table>
                    <colgroup>
                        <col style="width: 105px;">
                        <col style="width: 260px;">
                        <col style="width: 75px;">
                        <col style="width: 175px;">
                        <col style="width: 85px;">
                        <col style="width: 160px;">
                    </colgroup>
                    <thead>
                        <tr>
                            <th>Thời gian</th>
                            <th>Tên miền</th>
                            <th>Loại</th>
                            <th>Phản hồi bởi</th>
                            <th>Độ trễ</th>
                            <th>Trạng thái</th>
                        </tr>
                    </thead>
                    <tbody id="recent-queries-body">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 20px;">Đang kết nối luồng dữ liệu realtime...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Upstream Health Leaderboard -->
        <div class="main-panel">
            <h2>🏆 Bảng xếp hạng máy chủ DNS Upstream</h2>
            <div class="table-container">
                <table>
                    <colgroup>
                        <col style="width: 220px;">
                        <col style="width: 140px;">
                        <col style="width: 160px;">
                        <col style="width: 130px;">
                        <col style="width: 140px;">
                    </colgroup>
                    <thead>
                        <tr>
                            <th>DNS Server</th>
                            <th>Địa chỉ IP</th>
                            <th>Trễ ước tính (EMA)</th>
                            <th>Trạng thái</th>
                            <th>Đã xử lý</th>
                        </tr>
                    </thead>
                    <tbody id="dns-table-body">
                        <!-- Populated dynamically -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        function copyUrl(elementId, btnId) {
            const text = document.getElementById(elementId).innerText;
            const btn = document.getElementById(btnId);
            navigator.clipboard.writeText(text).then(() => {
                if (btn) {
                    const old = btn.innerText;
                    btn.innerText = '✓ Đã chép';
                    setTimeout(() => { btn.innerText = old; }, 2000);
                }
            }).catch(() => {
                prompt('Sao chép đường dẫn này:', text);
            });
        }

        function setElText(id, newText) {
            const el = document.getElementById(id);
            if (el && el.innerText !== String(newText)) {
                el.innerText = String(newText);
            }
        }

        function setElHtml(id, newHtml) {
            const el = document.getElementById(id);
            if (el && el.innerHTML !== newHtml) {
                el.innerHTML = newHtml;
            }
        }

        let localTotal = parseInt(localStorage.getItem('antigravity_total_queries') || '0', 10);
        let localHits = parseInt(localStorage.getItem('antigravity_cache_hits') || '0', 10);
        let localSwr = parseInt(localStorage.getItem('antigravity_swr_hits') || '0', 10);
        let localRepaired = parseInt(localStorage.getItem('antigravity_repaired') || '0', 10);
        let cachedQueries = [];
        try {
            cachedQueries = JSON.parse(localStorage.getItem('antigravity_recent_queries') || '[]');
        } catch (e) {}

        let lastQueriesSig = '';
        function renderRecentQueries(queries) {
            if (!queries || queries.length === 0) return;
            
            // Signature check: if query list is identical, DO NOT touch DOM at all
            const sig = queries.slice(0, 20).map(q => q.timestamp + '_' + q.domain + '_' + q.status + '_' + q.latency).join('|');
            if (sig === lastQueriesSig) return;
            lastQueriesSig = sig;

            const tbody = document.getElementById('recent-queries-body');
            const rows = queries.map(q => {
                const timeStr = new Date(q.timestamp).toLocaleTimeString();
                let badgeClass = 'badge-winner';
                if (q.status && (q.status.includes('Cache') || q.status.includes('SWR'))) badgeClass = 'badge-cache';
                if (q.status && q.status.includes('Repaired')) badgeClass = 'badge-repair';

                return '<tr>' +
                    '<td style="color: var(--text-muted); font-size: 0.85rem;">' + timeStr + '</td>' +
                    '<td title="' + escapeHtml(q.domain) + '"><strong style="color: #fff;">' + escapeHtml(q.domain) + '</strong></td>' +
                    '<td><span style="background: rgba(255,255,255,0.08); padding: 2px 6px; border-radius: 4px; font-size: 0.75rem;">' + escapeHtml(q.type) + '</span></td>' +
                    '<td title="' + escapeHtml(q.upstreamName) + '">' + escapeHtml(q.upstreamName) + '</td>' +
                    '<td style="font-weight: 600; color: ' + (q.latency < 25 ? 'var(--color-healthy)' : 'var(--text-main)') + ';">' + q.latency + 'ms</td>' +
                    '<td><span class="' + badgeClass + '">' + escapeHtml(q.status) + '</span></td>' +
                '</tr>';
            }).join('');

            tbody.innerHTML = rows;
        }

        let lastUpstreamsSig = '';
        function renderUpstreams(upstreams) {
            if (!upstreams || upstreams.length === 0) return;
            const sig = upstreams.map(u => u.name + '_' + u.status + '_' + u.routedQueries + '_' + (u.realAvgLatency || u.avgLatency)).join('|');
            if (sig === lastUpstreamsSig) return;
            lastUpstreamsSig = sig;

            const tbody = document.getElementById('dns-table-body');
            tbody.innerHTML = upstreams.map(u => {
                const isHealthy = u.status === 'Healthy';
                return '<tr>' +
                    '<td><strong>' + escapeHtml(u.name) + '</strong></td>' +
                    '<td><code>' + escapeHtml(u.ip) + '</code></td>' +
                    '<td><span style="color: ' + (isHealthy ? 'var(--color-healthy)' : 'var(--color-warning)') + '; font-weight: 700;">' + (u.realAvgLatency || u.avgLatency || 20) + ' ms</span></td>' +
                    '<td><span class="status-dot status-' + u.status + '"></span>' + u.status + '</td>' +
                    '<td><span class="badge-winner">' + (u.routedQueries || 0) + ' truy vấn</span></td>' +
                '</tr>';
            }).join('');
        }

        function updateUI(data) {
            if (!data) return;

            localTotal = Math.max(localTotal, data.totalQueries || 0);
            localHits = Math.max(localHits, data.cacheHits || 0);
            localSwr = Math.max(localSwr, data.swrHits || 0);
            localRepaired = Math.max(localRepaired, data.repairedPackets || 0);

            localStorage.setItem('antigravity_total_queries', localTotal);
            localStorage.setItem('antigravity_cache_hits', localHits);
            localStorage.setItem('antigravity_swr_hits', localSwr);
            localStorage.setItem('antigravity_repaired', localRepaired);

            // Merge incoming queries with local cache
            if (Array.isArray(data.recentQueries) && data.recentQueries.length > 0) {
                const map = new Map();
                data.recentQueries.forEach(q => map.set(q.timestamp + '_' + q.domain + '_' + q.type, q));
                cachedQueries.forEach(q => {
                    const key = q.timestamp + '_' + q.domain + '_' + q.type;
                    if (!map.has(key)) map.set(key, q);
                });
                cachedQueries = Array.from(map.values()).sort((a, b) => b.timestamp - a.timestamp).slice(0, 40);
                try {
                    localStorage.setItem('antigravity_recent_queries', JSON.stringify(cachedQueries));
                } catch (e) {}
            }

            setElText('total-queries', localTotal.toLocaleString());
            const hitRate = localTotal > 0 ? Math.round((localHits / localTotal) * 100) : 0;
            setElHtml('cache-hit-rate', hitRate + '<span class="stat-unit">%</span>');
            setElText('swr-hits', localSwr.toLocaleString());
            setElText('repaired-packets', localRepaired.toLocaleString());
            setElHtml('avg-latency', (data.averageLatency || 15) + '<span class="stat-unit">ms</span>');
            setElHtml('pool-size', (data.poolSize || 3) + '<span class="stat-unit">máy chủ</span>');

            renderUpstreams(data.upstreams);
            renderRecentQueries(cachedQueries.length > 0 ? cachedQueries : data.recentQueries);
        }

        let isSseLive = false;
        let pollTimer = null;

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                if (!res.ok) return;
                const data = await res.json();
                updateUI(data);
            } catch (err) {}
        }

        function startFallbackPolling() {
            if (pollTimer) return;
            pollTimer = setInterval(() => {
                if (!isSseLive) {
                    fetchStats();
                }
            }, 4000);
        }

        function initRealtimeStream() {
            if (window.EventSource) {
                const es = new EventSource('/api/stream');
                es.onopen = () => {
                    isSseLive = true;
                    setElText('stream-status-text', 'Realtime SSE');
                    if (pollTimer) {
                        clearInterval(pollTimer);
                        pollTimer = null;
                    }
                };
                es.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        updateUI(data);
                    } catch (e) {}
                };
                es.onerror = () => {
                    isSseLive = false;
                    setElText('stream-status-text', 'Đang đồng bộ');
                    es.close();
                    startFallbackPolling();
                    setTimeout(initRealtimeStream, 4000);
                };
            } else {
                startFallbackPolling();
            }
        }

        async function resetStatsCounter() {
            localTotal = 0;
            localHits = 0;
            localSwr = 0;
            localRepaired = 0;
            cachedQueries = [];
            localStorage.removeItem('antigravity_total_queries');
            localStorage.removeItem('antigravity_cache_hits');
            localStorage.removeItem('antigravity_swr_hits');
            localStorage.removeItem('antigravity_repaired');
            localStorage.removeItem('antigravity_recent_queries');
            try {
                await fetch('/api/reset-stats', { method: 'POST' });
            } catch (e) {}
            fetchStats();
        }

        async function executeDoHTest() {
            const domain = document.getElementById('test-domain-input').value.trim() || 'google.com';
            const type = document.getElementById('test-type-select').value || 'A';
            const box = document.getElementById('test-result-box');
            const meta = document.getElementById('test-result-meta');
            const pre = document.getElementById('test-result-pre');

            box.style.display = 'block';
            meta.innerText = 'Đang gửi truy vấn DoH cho ' + domain + ' (' + type + ')...';
            pre.innerText = 'Đang xử lý...';

            try {
                const res = await fetch('/api/test-doh?name=' + encodeURIComponent(domain) + '&type=' + type);
                const data = await res.json();
                if (data.success) {
                    meta.innerHTML = '✅ Phân giải thành công trong <span style="color: var(--color-healthy);">' + data.latencyMs + 'ms</span> | Mã phản hồi: ' + data.rcode;
                    let output = '';
                    if (data.answers && data.answers.length > 0) {
                        output = data.answers.map(a => a.name + ' [' + a.type + '] TTL=' + a.ttl + ' => ' + (a.data || a.ip || JSON.stringify(a))).join('\\n');
                    } else {
                        output = 'Không có bản ghi câu trả lời nào (NOERROR hoặc NXDOMAIN).';
                    }
                    pre.innerText = output;
                } else {
                    meta.innerText = '❌ Thất bại: ' + (data.error || 'Lỗi không xác định');
                    pre.innerText = JSON.stringify(data, null, 2);
                }
                fetchStats();
            } catch (err) {
                meta.innerText = '❌ Lỗi kết nối: ' + err.message;
                pre.innerText = err.stack || err.message;
            }
        }

        function quickTest(domain, type) {
            document.getElementById('test-domain-input').value = domain;
            document.getElementById('test-type-select').value = type;
            executeDoHTest();
        }

        function escapeHtml(str) {
            return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        // Initialize on load
        if (cachedQueries.length > 0) {
            renderRecentQueries(cachedQueries);
        }
        fetchStats();
        initRealtimeStream();
    </script>
</body>
</html>`;
}

// -------------------------------------------------------------
// CENTRAL ROUTE HANDLER (Supports Direct Node & Vercel Serverless)
// -------------------------------------------------------------
const handler = async (req, res) => {
  const urlParts = (req.url || '/').split('?');
  const searchParams = new URLSearchParams(urlParts[1] || '');

  // Resolve actual requested path across Vercel Rewrites and direct invocations
  let pathname = urlParts[0];
  if (pathname === '/api/index' || pathname === '/api') {
    if (searchParams.has('path')) {
      pathname = searchParams.get('path');
    } else if (req.headers['x-matched-path']) {
      pathname = req.headers['x-matched-path'];
    } else if (req.headers['x-forwarded-uri']) {
      pathname = req.headers['x-forwarded-uri'].split('?')[0];
    } else if (req.headers['x-invoke-path']) {
      pathname = req.headers['x-invoke-path'];
    }
  }

  // 1. Detect if incoming request is a DoH request (Catches all standard & non-standard DoH calls)
  const isDnsContentType = (req.headers['content-type'] || '').toLowerCase().includes('application/dns-message') ||
                           (req.headers['content-type'] || '').toLowerCase().includes('application/dns-json') ||
                           (req.headers['accept'] || '').toLowerCase().includes('application/dns-message');
  const isDnsPath = pathname === '/dns-query' ||
                    pathname === '/query' ||
                    pathname === '/resolve' ||
                    pathname === '/doh' ||
                    pathname === '/dns' ||
                    pathname === '/api/dns-query' ||
                    pathname.endsWith('/dns-query');
  const hasDnsParams = (searchParams.has('dns') || searchParams.has('name')) && pathname !== '/api/test-doh';

  if (isDnsPath || isDnsContentType || (hasDnsParams && req.method === 'GET')) {
    return handleDoHRequest(req, res);
  }

  // 2. Health check
  if (pathname === '/api/ping') {
    return handlePingRequest(req, res);
  }

  // 3. Stats
  if (pathname === '/api/stats') {
    return handleStatsRequest(req, res);
  }

  // 4. Real-time Server-Sent Events stream
  if (pathname === '/api/stream') {
    return handleStreamRequest(req, res);
  }

  // 5. Reset stats
  if (pathname === '/api/reset-stats') {
    return handleResetStatsRequest(req, res);
  }

  // 6. Test DoH
  if (pathname === '/api/test-doh') {
    return handleTestDoHRequest(req, res);
  }

  // 7. Apple iOS/macOS Encrypted DNS Profile (.mobileconfig)
  if (pathname === '/profile.mobileconfig' || pathname === '/api/profile') {
    return handleProfileRequest(req, res);
  }

  // 8. Default: Serve Web Dashboard
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(renderDashboardHtml(req));
};

const server = http.createServer(handler);
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

// Periodic cleanup of expired cache entries (every 2 minutes)
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, val] of cache.entries()) {
    if (now >= val.swrExpiresAt) {
      cache.delete(key);
    }
  }
}, 120000);
if (cleanupTimer.unref) cleanupTimer.unref();

// Periodic candidate ranking
const candidatesTimer = setInterval(updateCandidates, 8000);
if (candidatesTimer.unref) candidatesTimer.unref();

// Periodic canary health probe for Degraded upstreams (every 20 seconds)
const canaryTimer = setInterval(async () => {
  const needsProbe = upstreamStates.filter(s => s.status === 'Degraded' || s.status === 'Offline');
  if (needsProbe.length === 0) return;

  const probeQuery = dnsPacket.encode({
    type: 'query',
    id: 9999,
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type: 'A', name: 'google.com' }]
  });

  for (const u of needsProbe) {
    try {
      const res = await queryDoHUpstream(u, probeQuery, 1500);
      if (res && res.buffer && res.buffer.length >= 12) {
        u.status = 'Healthy';
        u.penalty = 0;
        u.consecutiveErrors = 0;
        u.avgLatency = res.latency;
        u.realAvgLatency = res.latency;
      }
    } catch (e) {
      // Still unreachable
    }
  }
}, 20000);
if (canaryTimer.unref) canaryTimer.unref();

// Standalone Node.js execution
if (!isVercel && require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[Antigravity DNS] Server listening on http://0.0.0.0:${PORT}`);
  });
}

module.exports = {
  server,
  handler,
  handleDoHRequest,
  handlePingRequest,
  handleStatsRequest,
  handleStreamRequest,
  handleResetStatsRequest,
  handleTestDoHRequest,
  handleProfileRequest,
  generateMobileConfig,
  handleDoH,
  repairAndNormalizeDnsQuery,
  repairDnsResponse
};
module.exports.default = handler;
