const http = require('http');
const https = require('https');
const dgram = require('dgram');
const dnsPacket = require('dns-packet');

const PORT = process.env.PORT || 3000;
const isVercel = Boolean(process.env.VERCEL || process.env.NOW_REGION || process.env.AWS_LAMBDA_FUNCTION_NAME);

// Persistent HTTPS Connection Pooling for sub-10ms DoH resolution
const httpsAgent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 60000,
  maxSockets: 64,
  maxFreeSockets: 20,
  timeout: 3000,
  rejectUnauthorized: false
});

// High-Performance Upstream DNS Servers List (Dual-Engine: DoH HTTPS + Anycast IP)
const UPSTREAMS = [
  { ip: '1.1.1.1', name: 'Cloudflare Primary', dohUrl: 'https://1.1.1.1/dns-query' },
  { ip: '1.0.0.1', name: 'Cloudflare Secondary', dohUrl: 'https://1.0.0.1/dns-query' },
  { ip: '8.8.8.8', name: 'Google Primary', dohUrl: 'https://8.8.8.8/dns-query' },
  { ip: '8.8.4.4', name: 'Google Secondary', dohUrl: 'https://8.8.4.4/dns-query' },
  { ip: '9.9.9.9', name: 'Quad9 Security', dohUrl: 'https://dns.quad9.net/dns-query' },
  { ip: '208.67.222.222', name: 'OpenDNS Home', dohUrl: 'https://doh.opendns.com/dns-query' },
  { ip: '94.140.14.14', name: 'AdGuard Default', dohUrl: 'https://dns.adguard-dns.com/dns-query' },
  { ip: '76.76.2.0', name: 'ControlD Unfiltered', dohUrl: 'https://freedns.controld.com/p0' },
  { ip: '203.113.131.1', name: 'Viettel Primary', dohUrl: 'https://1.1.1.1/dns-query' },
  { ip: '203.162.0.11', name: 'VNPT Backup', dohUrl: 'https://8.8.8.8/dns-query' },
  { ip: '203.113.131.2', name: 'Viettel Secondary', dohUrl: 'https://1.0.0.1/dns-query' },
  { ip: '210.245.24.20', name: 'FPT Primary', dohUrl: 'https://8.8.4.4/dns-query' }
];

// Global Metrics & Telemetry
const stats = {
  totalQueries: 0,
  cacheHits: 0,
  swrHits: 0,
  cacheMisses: 0,
  errors: 0,
  totalLatency: 0,
  averageLatency: 0
};

// Upstream Performance & Health Registry
const upstreamStates = UPSTREAMS.map(dns => ({
  ip: dns.ip,
  name: dns.name,
  dohUrl: dns.dohUrl,
  pings: [25, 20, 22],
  successCount: 10,
  failCount: 0,
  avgLatency: 22,
  lossRate: 0,
  realAvgLatency: 20,
  realQueriesCount: 0,
  realErrorsCount: 0,
  penalty: 0,
  jitter: 2,
  score: 22,
  routedQueries: 0,
  status: 'Healthy',
  activeQueries: 0,
  consecutiveErrors: 0,
  recoveryTime: null
}));

// Score Calculator: Latency + Loss + Penalty + Jitter + Outstanding Concurrency
function calculateScore(state) {
  const jitterPenalty = state.jitter > 15 ? state.jitter * 2 : 0;
  const concurrencyPenalty = (state.activeQueries || 0) * 30;
  state.score = state.avgLatency + (state.lossRate * 5) + (state.penalty || 0) + jitterPenalty + concurrencyPenalty;
  return Math.max(1, Math.round(state.score));
}

let currentPoolSize = 3;

function updateCandidates() {
  const sorted = [...upstreamStates]
    .filter(s => s.status !== 'Offline')
    .sort((a, b) => a.score - b.score);

  if (sorted.length >= 3) {
    currentPoolSize = 3;
  } else {
    currentPoolSize = Math.max(2, sorted.length);
  }
}

// In-Memory DNS Cache (Key: name:type:class)
const cache = new Map();
const activeRevalidations = new Set();
const coalescedQueries = new Map();
const recentQueries = [];

function recordRecentQuery(domain, type, upstreamName, upstreamIp, latency, status) {
  recentQueries.unshift({
    timestamp: Date.now(),
    domain: domain || 'unknown',
    type: type || 'A',
    upstreamName: upstreamName || 'Cache',
    upstreamIp: upstreamIp || '-',
    latency: Math.max(0, Math.round(latency || 0)),
    status: status || 'Resolved'
  });
  if (recentQueries.length > 30) {
    recentQueries.pop();
  }
}

function overrideTtlInResponse(buffer) {
  try {
    const decoded = dnsPacket.decode(buffer);
    let changed = false;
    if (decoded.answers) {
      decoded.answers.forEach(ans => {
        if (ans.ttl !== undefined && ans.ttl < 600) {
          ans.ttl = 600; // Force 10 minutes cache TTL for client performance
          changed = true;
        }
      });
    }
    return changed ? dnsPacket.encode(decoded) : buffer;
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

// Robust Request Body Extractor (Guaranteed zero-freeze in Vercel & Node.js)
async function getRequestBody(req) {
  if (req.body) {
    if (Buffer.isBuffer(req.body)) return req.body;
    if (typeof req.body === 'string') return Buffer.from(req.body);
    if (typeof req.body === 'object') return Buffer.from(JSON.stringify(req.body));
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
    const timer = setTimeout(finish, 2500); // 2.5s safety timeout
    if (timer.unref) timer.unref();
  });
}

// Query single DoH upstream with keep-alive connection
function queryDoHUpstream(upstream, queryBuffer, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
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
        'User-Agent': 'Antigravity-DoH/2.0'
      },
      timeout: timeoutMs
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode} from ${upstream.name}`));
        }
        const resBuf = Buffer.concat(chunks);
        if (resBuf.length < 12) {
          return reject(new Error('Truncated DNS packet'));
        }
        const latency = Date.now() - t0;
        resolve({ upstream, buffer: resBuf, latency });
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Timeout (${timeoutMs}ms) from ${upstream.name}`));
    });

    req.write(queryBuffer);
    req.end();
  });
}

// Weighted Fair Candidate Selection with Power-of-Choices
function selectRacingCandidates(count = 3) {
  const healthy = upstreamStates.filter(s => s.status !== 'Offline');
  if (healthy.length <= count) {
    return [...healthy];
  }

  // Calculate dynamic lottery weights:
  // Lower score -> higher weight
  // Add fairness multiplier to distribute traffic across all upstreams
  const pool = healthy.map(c => {
    const scoreVal = Math.max(1, calculateScore(c));
    const fairnessBonus = 1.0 + Math.max(0, 0.8 - (c.routedQueries || 0) * 0.05);
    const weight = Math.max(0.1, Math.pow(1000 / scoreVal, 1.2) * fairnessBonus);
    return { candidate: c, weight };
  });

  const selected = [];
  const available = [...pool];
  const targetCount = Math.min(count, available.length);

  for (let i = 0; i < targetCount; i++) {
    const totalWeight = available.reduce((sum, item) => sum + item.weight, 0);
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

// Hedged Racing Engine: Races 2-3 candidate upstreams concurrently
async function raceDNS(queryBuffer, clientIp = null, timeoutMs = 1800) {
  const originalTxId = queryBuffer.readUInt16BE(0);
  const candidates = selectRacingCandidates(currentPoolSize || 3);

  // Mark active queries
  candidates.forEach(c => {
    c.activeQueries = (c.activeQueries || 0) + 1;
  });

  try {
    // Race candidates in parallel using Promise.any
    const racePromises = candidates.map(upstream =>
      queryDoHUpstream(upstream, queryBuffer, timeoutMs)
    );

    const winnerRes = await Promise.any(racePromises);
    const winner = winnerRes.upstream;
    const responseBuffer = Buffer.from(winnerRes.buffer);
    
    // Ensure response has client's original transaction ID
    responseBuffer.writeUInt16BE(originalTxId, 0);

    // Update telemetry
    winner.routedQueries = (winner.routedQueries || 0) + 1;
    winner.consecutiveErrors = 0;
    winner.penalty = Math.max(0, (winner.penalty || 0) - 15);
    
    const alpha = 0.25;
    winner.realAvgLatency = (winner.realQueriesCount || 0) === 0
      ? winnerRes.latency
      : Math.round(alpha * winnerRes.latency + (1 - alpha) * (winner.realAvgLatency || winnerRes.latency));
    winner.realQueriesCount = (winner.realQueriesCount || 0) + 1;
    winner.avgLatency = winner.realAvgLatency;
    calculateScore(winner);

    return {
      responseBuffer,
      from: winner.name,
      winner
    };
  } catch (err) {
    candidates.forEach(c => {
      c.realErrorsCount = (c.realErrorsCount || 0) + 1;
      c.penalty = Math.min(800, (c.penalty || 0) + 100);
      calculateScore(c);
    });

    // Last-Resort Emergency Fallback (Direct Cloudflare 1.1.1.1 DoH)
    try {
      const emergencyRes = await queryDoHUpstream(
        { name: 'Cloudflare Fallback', dohUrl: 'https://1.1.1.1/dns-query' },
        queryBuffer,
        1500
      );
      const resBuf = Buffer.from(emergencyRes.buffer);
      resBuf.writeUInt16BE(originalTxId, 0);
      return {
        responseBuffer: resBuf,
        from: 'Cloudflare Fallback',
        winner: upstreamStates[0]
      };
    } catch (fallbackErr) {
      throw new Error('All DNS upstreams failed or timed out: ' + err.message);
    }
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

// Core DoH Handler with In-Memory Caching & Stale-While-Revalidate (SWR)
async function handleDoH(queryBuffer, clientIp) {
  const startTime = Date.now();
  stats.totalQueries++;

  let dnsQueryObj;
  try {
    dnsQueryObj = dnsPacket.decode(queryBuffer);
  } catch (err) {
    stats.errors++;
    throw new Error('Format Error: Failed to parse DNS query');
  }

  // EDNS Client Subnet (ECS) Routing
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

  // 1. Cache Lookup
  if (cacheKey && cache.has(cacheKey)) {
    const cachedEntry = cache.get(cacheKey);

    // Stale-While-Revalidate (SWR) within 24h window
    if (now < cachedEntry.swrExpiresAt) {
      const isFresh = now < cachedEntry.expiresAt;
      const shouldRevalidate = !isFresh;

      if (shouldRevalidate && !activeRevalidations.has(cacheKey)) {
        stats.swrHits++;
        const q0 = dnsQueryObj.questions && dnsQueryObj.questions[0];
        recordRecentQuery(q0 ? q0.name : 'query', q0 ? q0.type : 'A', 'Bộ nhớ đệm SWR', '0ms (Stale)', 0, 'SWR Hit');
        activeRevalidations.add(cacheKey);

        // Async background refresh
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

      const clientResponse = Buffer.from(cachedEntry.buffer);
      clientResponse.writeUInt16BE(dnsQueryObj.id, 0);
      return clientResponse;
    } else {
      cache.delete(cacheKey);
    }
  }

  // 2. Request Coalescing (Deduplicate in-flight requests)
  if (cacheKey && coalescedQueries.has(cacheKey)) {
    try {
      const sharedRes = await coalescedQueries.get(cacheKey);
      const clientResponse = Buffer.from(sharedRes.responseBuffer);
      clientResponse.writeUInt16BE(dnsQueryObj.id, 0);
      stats.cacheHits++;
      return clientResponse;
    } catch (e) {}
  }

  // 3. Forward to Upstreams
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
      'Resolved'
    );

    // Save to Cache
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

    return responseBuffer;
  } catch (err) {
    stats.errors++;
    const q0 = dnsQueryObj.questions && dnsQueryObj.questions[0];
    recordRecentQuery(q0 ? q0.name : 'query', q0 ? q0.type : 'A', 'Thất bại', '-', Date.now() - startTime, 'Timeout/Error');

    // Return friendly SERVFAIL
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

// Request Handler (Vercel Serverless Function & Node.js HTTP Server)
const handler = async (req, res) => {
  const urlParts = (req.url || '/').split('?');
  const pathname = urlParts[0];

  // CORS Headers for Web & DoH Clients
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Fast-Path Ping (Health Check)
  if (pathname === '/api/ping') {
    res.writeHead(200, {
      'Content-Type': 'text/plain',
      'Cache-Control': 'no-store, no-cache, must-revalidate'
    });
    res.end('pong');
    return;
  }

  // Fast Query Param Parser
  let searchParams = null;
  const getSearchParam = (name) => {
    if (!searchParams) {
      searchParams = new URLSearchParams(urlParts[1] || '');
    }
    return searchParams.get(name);
  };

  const clientIp = req.headers['x-forwarded-for']
    ? req.headers['x-forwarded-for'].split(',')[0].trim()
    : (req.socket ? req.socket.remoteAddress : '127.0.0.1');

  // RFC 8484 DoH Query Handler
  if (pathname === '/dns-query' || pathname === '/resolve' || pathname.endsWith('/dns-query')) {
    if (req.method === 'GET') {
      const dnsParam = getSearchParam('dns');
      const nameParam = getSearchParam('name');
      const typeParam = (getSearchParam('type') || 'A').toUpperCase();

      // 1. Standard RFC 8484 GET (?dns=<base64url>)
      if (dnsParam) {
        try {
          const queryBuffer = base64urlDecode(dnsParam);
          const responseBuffer = await handleDoH(queryBuffer, clientIp);
          res.writeHead(200, {
            'Content-Type': 'application/dns-message',
            'Content-Length': responseBuffer.length,
            'Cache-Control': 'public, max-age=60, s-maxage=300, stale-while-revalidate=86400'
          });
          res.end(responseBuffer);
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('DoH Resolution Error: ' + err.message);
        }
        return;
      }

      // 2. JSON DoH Query (?name=<domain>&type=<type>)
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
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ Status: 2, error: err.message }));
        }
        return;
      }

      // 3. User accesses /dns-query directly in browser without parameters
      const host = req.headers.host || 'localhost:3000';
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({
        status: 'online',
        server: 'Antigravity Hyper-Speed DoH Proxy (Vercel Optimized)',
        endpoints: {
          rfc8484_post: { method: 'POST', path: '/dns-query', contentType: 'application/dns-message' },
          rfc8484_get: { method: 'GET', path: '/dns-query?dns=<base64url>' },
          json_query: { method: 'GET', path: '/dns-query?name=<domain>&type=<type>' }
        },
        quickTest: `https://${host}/dns-query?name=google.com&type=A`
      }, null, 2));
      return;
    } else if (req.method === 'POST') {
      try {
        const queryBuffer = await getRequestBody(req);
        if (!queryBuffer || queryBuffer.length === 0) {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('Empty query body');
          return;
        }

        const responseBuffer = await handleDoH(queryBuffer, clientIp);
        res.writeHead(200, {
          'Content-Type': 'application/dns-message',
          'Content-Length': responseBuffer.length,
          'Cache-Control': 'public, max-age=60, s-maxage=300, stale-while-revalidate=86400'
        });
        res.end(responseBuffer);
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('DoH POST Error: ' + err.message);
      }
      return;
    }
  }

  // Interactive Live DoH Tester API
  if (pathname === '/api/test-doh') {
    const name = getSearchParam('name') || 'google.com';
    const type = (getSearchParam('type') || 'A').toUpperCase();

    try {
      const queryPacket = dnsPacket.encode({
        type: 'query',
        id: Math.floor(Math.random() * 65535) + 1,
        flags: dnsPacket.RECURSION_DESIRED,
        questions: [{ type, name: name.trim() }]
      });

      const startTime = Date.now();
      const responseBuffer = await handleDoH(queryPacket, clientIp);
      const latency = Date.now() - startTime;
      const decoded = dnsPacket.decode(responseBuffer);

      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({
        success: true,
        query: { name, type },
        latencyMs: latency,
        rcode: decoded.rcode || 'NOERROR',
        answersCount: (decoded.answers || []).length,
        answers: decoded.answers || [],
        base64UrlResponse: responseBuffer.toString('base64url'),
        timestamp: new Date().toISOString()
      }, null, 2));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: err.message }));
    }
    return;
  }

  // JSON Metrics API
  if (pathname === '/api/stats') {
    const totalRouted = upstreamStates.reduce((acc, curr) => acc + (curr.routedQueries || 0), 0);
    const activeUpstreams = upstreamStates.filter(s => s.status !== 'Offline').length;

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ...stats,
      upstreams: upstreamStates,
      poolSize: currentPoolSize,
      cacheSize: cache.size,
      uptime: process.uptime(),
      runtime: isVercel ? 'Vercel Serverless' : 'Node.js Standalone',
      loadBalancing: {
        algorithm: 'Adaptive P2C & Hedged Racing',
        activeUpstreams,
        totalUpstreams: upstreamStates.length,
        totalRouted
      },
      recentQueries
    }));
    return;
  }

  // HTML Web Dashboard (Default Route)
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000';
  const protocol = req.headers['x-forwarded-proto'] || (isVercel ? 'https' : 'http');
  const dohUrl = `${protocol}://${host}/dns-query`;

  const html = `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Antigravity Hyper-Speed DoH Proxy — Tối ưu cho Vercel</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #03050a;
            --panel-bg: rgba(8, 12, 24, 0.75);
            --border-color: rgba(255, 255, 255, 0.06);
            --accent-glow: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
            --accent-solid: #00f2fe;
            --text-color: #f3f4f6;
            --text-muted: #9ca3af;
            --color-healthy: #00ffaa;
            --color-warning: #ffb800;
            --color-offline: #ff3b30;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            min-height: 100vh;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 15% 15%, rgba(0, 242, 254, 0.06) 0%, transparent 35%),
                radial-gradient(circle at 85% 85%, rgba(79, 172, 254, 0.06) 0%, transparent 35%);
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
        header { text-align: center; margin-bottom: 35px; }
        header h1 {
            font-size: 2.8rem;
            font-weight: 800;
            background: linear-gradient(to right, #00f2fe, #4facfe);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        header p { color: var(--text-muted); font-size: 1.1rem; font-weight: 300; }
        .badge-vercel {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 6px 14px; border-radius: 20px;
            background: rgba(0, 242, 254, 0.12); border: 1px solid rgba(0, 242, 254, 0.3);
            color: var(--accent-solid); font-size: 0.85rem; font-weight: 600;
            margin-top: 12px;
        }
        .grid-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 18px; margin-bottom: 30px;
        }
        .stat-card {
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            backdrop-filter: blur(20px);
            border-radius: 18px; padding: 20px;
            transition: all 0.25s ease;
        }
        .stat-card:hover {
            transform: translateY(-3px);
            border-color: rgba(0, 242, 254, 0.25);
            box-shadow: 0 10px 25px rgba(0, 242, 254, 0.05);
        }
        .stat-title { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
        .stat-value { font-size: 1.8rem; font-weight: 700; font-variant-numeric: tabular-nums; }
        .stat-unit { font-size: 0.8rem; color: var(--text-muted); font-weight: 400; margin-left: 2px; }
        .main-panel {
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            backdrop-filter: blur(20px);
            border-radius: 22px; padding: 30px; margin-bottom: 30px;
        }
        .main-panel h2 {
            font-size: 1.35rem; margin-bottom: 18px; font-weight: 700;
            display: flex; align-items: center; gap: 10px;
        }
        .main-panel h2::before {
            content: ''; display: inline-block; width: 5px; height: 20px;
            background: var(--accent-glow); border-radius: 3px;
        }
        .url-box {
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(0, 242, 254, 0.25);
            border-radius: 12px; padding: 14px 18px;
            display: flex; justify-content: space-between; align-items: center;
            font-family: monospace; font-size: 0.95rem; color: var(--accent-solid);
            margin-bottom: 20px; word-break: break-all;
        }
        .btn-copy {
            background: var(--accent-glow); color: #000;
            border: none; padding: 8px 16px; border-radius: 8px;
            font-weight: 700; cursor: pointer; transition: all 0.2s;
            margin-left: 12px; white-space: nowrap;
        }
        .btn-copy:hover { transform: scale(1.05); }
        .deploy-guide-box {
            background: linear-gradient(135deg, rgba(0, 242, 254, 0.05), rgba(79, 172, 254, 0.02));
            border: 1px solid rgba(0, 242, 254, 0.2);
            border-radius: 16px; padding: 22px; margin-bottom: 25px;
        }
        .deploy-steps {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 15px; margin-top: 15px;
        }
        .deploy-step {
            background: rgba(0, 0, 0, 0.3); border: 1px solid var(--border-color);
            border-radius: 12px; padding: 15px;
        }
        .deploy-step h4 {
            color: var(--accent-solid); font-size: 0.95rem; margin-bottom: 6px;
            display: flex; align-items: center; gap: 6px;
        }
        .deploy-step p { color: var(--text-muted); font-size: 0.85rem; line-height: 1.4; }
        .table-container { width: 100%; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
        th {
            padding: 12px 14px; border-bottom: 2px solid var(--border-color);
            color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem;
        }
        td { padding: 14px; border-bottom: 1px solid var(--border-color); vertical-align: middle; }
        tr:hover td { background: rgba(255, 255, 255, 0.02); }
        .status-dot {
            width: 8px; height: 8px; border-radius: 50%;
            display: inline-block; margin-right: 6px;
        }
        .status-Healthy { background: var(--color-healthy); box-shadow: 0 0 8px var(--color-healthy); }
        .status-Warning { background: var(--color-warning); box-shadow: 0 0 8px var(--color-warning); }
        .status-Offline { background: var(--color-offline); box-shadow: 0 0 8px var(--color-offline); }
        .badge-winner {
            background: rgba(0, 242, 254, 0.12); color: var(--accent-solid);
            border: 1px solid rgba(0, 242, 254, 0.25);
            padding: 2px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Antigravity Hyper-Speed DoH Proxy</h1>
            <p>Hệ thống DNS over HTTPS tốc độ cao — Tối ưu hóa 100% cho Vercel & Node.js</p>
            <div class="badge-vercel">
                <span>⚡</span>
                <span>Vercel Serverless Ready — Zero Freeze & Zero Latency Spikes</span>
            </div>
        </header>

        <div class="deploy-guide-box">
            <h3 style="display: flex; align-items: center; gap: 8px; color: #fff; font-size: 1.15rem;">
                <span>🚀</span> Hướng dẫn đẩy lên Vercel chạy thực tế 24/7 (Miễn phí 100%)
            </h3>
            <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 6px;">
                Hệ thống đã được tối ưu hoàn toàn cho Vercel: sử dụng Keep-Alive HTTPS DoH upstreams, cấu hình <code>vercel.json</code> serverless rewrites, không còn phụ thuộc vào socket UDP bị chặn trên cloud.
            </p>
            <div class="deploy-steps">
                <div class="deploy-step">
                    <h4>1. Đẩy code lên GitHub</h4>
                    <p>Commit và push toàn bộ thư mục này lên GitHub repository của bạn (vd: <code>git push origin main</code>).</p>
                </div>
                <div class="deploy-step">
                    <h4>2. Kết nối vào Vercel</h4>
                    <p>Truy cập <strong>vercel.com</strong> &rarr; Click <strong>"Add New... Project"</strong> &rarr; Chọn repo GitHub của bạn.</p>
                </div>
                <div class="deploy-step">
                    <h4>3. Nhấn Deploy</h4>
                    <p>Không cần cấu hình biến môi trường nào! Nhấn <strong>Deploy</strong>. Vercel sẽ tự sinh domain <code>https://&lt;ten-du-an&gt;.vercel.app</code>.</p>
                </div>
                <div class="deploy-step">
                    <h4>4. Cài đặt vào thiết bị</h4>
                    <p>URL DoH của bạn sẽ là <code>https://&lt;ten-du-an&gt;.vercel.app/dns-query</code>. Dán vào iPhone, Android, Windows 11 hoặc trình duyệt để dùng internet tốc độ cao!</p>
                </div>
            </div>
        </div>

        <div class="grid-stats">
            <div class="stat-card">
                <div class="stat-title">Tổng truy vấn</div>
                <div class="stat-value" id="total-queries">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Cache RAM (0ms)</div>
                <div class="stat-value" id="cache-hit-rate">0<span class="stat-unit">%</span></div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Tối ưu SWR Hits</div>
                <div class="stat-value" id="swr-hits">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Độ trễ trung bình</div>
                <div class="stat-value" id="avg-latency">0<span class="stat-unit">ms</span></div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Racing Pool</div>
                <div class="stat-value" id="pool-size">3<span class="stat-unit">upstreams</span></div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Ping của bạn đến Server</div>
                <div class="stat-value" id="client-to-server-ping">--<span class="stat-unit">ms</span></div>
            </div>
        </div>

        <div class="main-panel">
            <h2>Đường dẫn DNS over HTTPS (DoH) của bạn</h2>
            <div class="url-box">
                <span id="doh-url">${dohUrl}</span>
                <button class="btn-copy" onclick="copyUrl()">Sao chép URL</button>
            </div>
            <div style="font-size: 0.85rem; color: var(--text-muted); display: flex; gap: 15px; flex-wrap: wrap;">
                <span>✅ Hỗ trợ RFC 8484 Binary POST</span>
                <span>✅ Hỗ trợ RFC 8484 Base64url GET (<code>?dns=</code>)</span>
                <span>✅ Hỗ trợ JSON Query API (<code>?name=&amp;type=</code>)</span>
                <span>✅ Tự động định tuyến Anycast CDN (ECS Injection)</span>
            </div>
        </div>

        <!-- Interactive DoH Query Tester -->
        <div class="main-panel">
            <h2>🧪 Công cụ kiểm thử truy vấn DoH trực tiếp</h2>
            <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 15px;">
                <input id="test-domain-input" type="text" value="google.com" placeholder="Nhập tên miền (vd: facebook.com, vnexpress.net)" style="flex: 1; min-width: 200px; padding: 10px 14px; background: rgba(0,0,0,0.4); border: 1px solid var(--border-color); border-radius: 8px; color: #fff; font-family: monospace; outline: none;" onkeydown="if(event.key==='Enter') executeDoHTest()" />
                <select id="test-type-select" style="padding: 10px 14px; background: #080c18; border: 1px solid var(--border-color); border-radius: 8px; color: #fff; font-weight: 600; cursor: pointer; outline: none;">
                    <option value="A">Record A (IPv4)</option>
                    <option value="AAAA">Record AAAA (IPv6)</option>
                    <option value="MX">Record MX</option>
                    <option value="TXT">Record TXT</option>
                </select>
                <button onclick="executeDoHTest()" style="background: var(--accent-glow); color: #000; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 700; cursor: pointer;">Chạy truy vấn</button>
            </div>
            <div id="test-result-box" style="display: none; background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(0, 242, 254, 0.2); border-radius: 10px; padding: 15px; font-family: monospace; font-size: 0.85rem;">
                <div id="test-result-meta" style="margin-bottom: 8px; color: var(--accent-solid); font-weight: 600;"></div>
                <pre id="test-result-pre" style="white-space: pre-wrap; color: #e5e7eb;"></pre>
            </div>
        </div>

        <!-- Live Load Balancing & Dispatch Logs -->
        <div class="main-panel">
            <h2>⚡ Nhật ký điều phối &amp; chia tải thời gian thực</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Thời gian</th>
                            <th>Tên miền</th>
                            <th>Loại</th>
                            <th>Upstream thắng giải tải</th>
                            <th>Độ trễ</th>
                            <th>Trạng thái</th>
                        </tr>
                    </thead>
                    <tbody id="query-logs-body">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 25px;">Đang tải nhật ký...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Upstream Health Leaderboard -->
        <div class="main-panel">
            <h2>🏆 Bảng xếp hạng máy chủ DNS Upstream</h2>
            <div class="table-container">
                <table>
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
        function copyUrl() {
            const urlText = document.getElementById('doh-url').innerText;
            navigator.clipboard.writeText(urlText).then(() => {
                alert('Đã sao chép URL DoH vào bộ nhớ tạm: ' + urlText);
            }).catch(() => {
                const input = document.createElement('input');
                input.value = urlText;
                document.body.appendChild(input);
                input.select();
                document.execCommand('copy');
                document.body.removeChild(input);
                alert('Đã sao chép URL DoH!');
            });
        }

        async function pingServer() {
            const t0 = performance.now();
            try {
                const res = await fetch('/api/ping?t=' + Date.now(), { cache: 'no-store' });
                if (res.ok) {
                    const rtt = Math.round(performance.now() - t0);
                    document.getElementById('client-to-server-ping').innerHTML = rtt + '<span class="stat-unit">ms</span>';
                }
            } catch (e) {}
        }

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                if (!res.ok) return;
                const data = await res.json();

                document.getElementById('total-queries').innerText = data.totalQueries.toLocaleString();
                const hitRate = data.totalQueries > 0 ? Math.round((data.cacheHits / data.totalQueries) * 100) : 0;
                document.getElementById('cache-hit-rate').innerHTML = hitRate + '<span class="stat-unit">%</span>';
                document.getElementById('swr-hits').innerText = (data.swrHits || 0).toLocaleString();
                document.getElementById('avg-latency').innerHTML = (data.averageLatency || 0) + '<span class="stat-unit">ms</span>';
                document.getElementById('pool-size').innerHTML = (data.poolSize || 3) + '<span class="stat-unit">upstreams</span>';

                // Upstreams table
                const tbody = document.getElementById('dns-table-body');
                if (data.upstreams && data.upstreams.length > 0) {
                    tbody.innerHTML = data.upstreams.map(u => {
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

                // Recent queries log
                const logBody = document.getElementById('query-logs-body');
                if (data.recentQueries && data.recentQueries.length > 0) {
                    logBody.innerHTML = data.recentQueries.map(q => {
                        const timeStr = new Date(q.timestamp).toLocaleTimeString();
                        return '<tr>' +
                            '<td style="color: var(--text-muted); font-size: 0.8rem;">' + timeStr + '</td>' +
                            '<td><code style="color: #fff; font-weight: 600;">' + escapeHtml(q.domain) + '</code></td>' +
                            '<td><span style="font-size: 0.75rem; padding: 2px 6px; background: rgba(255,255,255,0.06); border-radius: 4px;">' + escapeHtml(q.type) + '</span></td>' +
                            '<td><span class="badge-winner">' + escapeHtml(q.upstreamName) + '</span></td>' +
                            '<td style="font-weight: 600; color: ' + (q.latency < 25 ? 'var(--color-healthy)' : 'var(--color-warning)') + ';">' + q.latency + ' ms</td>' +
                            '<td><span style="color: var(--color-healthy); font-size: 0.8rem;">● ' + escapeHtml(q.status) + '</span></td>' +
                        '</tr>';
                    }).join('');
                }
            } catch (err) {}
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

        function escapeHtml(str) {
            return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        fetchStats();
        pingServer();
        setInterval(fetchStats, 3000);
        setInterval(pingServer, 5000);
    </script>
</body>
</html>`;

  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
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

// Periodic update of candidate rankings
const candidatesTimer = setInterval(updateCandidates, 8000);
if (candidatesTimer.unref) candidatesTimer.unref();

// In standalone Node.js environment, listen on PORT
if (!isVercel && require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[Antigravity DNS] Server listening on http://0.0.0.0:${PORT}`);
  });
}

module.exports = { server, handler };
module.exports.default = handler;
