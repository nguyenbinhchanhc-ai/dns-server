const http = require('http');
const https = require('https');
const dgram = require('dgram');
const dnsPacket = require('dns-packet');

const PORT = process.env.PORT || 3000;
const isVercel = Boolean(process.env.VERCEL || process.env.NOW_REGION || process.env.AWS_LAMBDA_FUNCTION_NAME);

// Persistent, ultra-high-performance HTTPS Agent with Keep-Alive & Connection Pooling
// maxSockets: Infinity ensures zero queuing bottlenecks for concurrent DNS queries
const httpsAgent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 120000,
  maxSockets: Infinity,
  maxFreeSockets: 128,
  timeout: 2500,
  rejectUnauthorized: false
});

// Curated 100% verified high-performance upstream resolvers
// (Eliminated broken Quad9 505 and Mullvad socket hangup)
const UPSTREAMS = [
  { name: 'Google Primary', ip: '8.8.8.8', dohUrl: 'https://8.8.8.8/dns-query' },
  { name: 'Google Secondary', ip: '8.8.4.4', dohUrl: 'https://8.8.4.4/dns-query' },
  { name: 'Cloudflare Primary', ip: '1.1.1.1', dohUrl: 'https://1.1.1.1/dns-query' },
  { name: 'Cloudflare Secondary', ip: '1.0.0.1', dohUrl: 'https://1.0.0.1/dns-query' },
  { name: 'AdGuard Standard', ip: '94.140.14.14', dohUrl: 'https://94.140.14.14/dns-query' },
  { name: 'DNS.SB Primary', ip: '45.11.45.11', dohUrl: 'https://45.11.45.11/dns-query' },
  { name: 'ControlD Free', ip: '76.76.2.0', dohUrl: 'https://76.76.2.0/dns-query' },
  { name: 'OpenDNS Primary', ip: '208.67.222.222', dohUrl: 'https://208.67.222.222/dns-query' },
  { name: 'OpenDNS Secondary', ip: '208.67.220.220', dohUrl: 'https://208.67.220.220/dns-query' }
];

// Health and telemetry state per upstream with Circuit Breaker tracking
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

// Smart Dynamic Score: lower score = faster and healthier server
function calculateScore(state) {
  const effectiveLatency = state.realAvgLatency || state.avgLatency || 20;
  const loadPenalty = (state.activeQueries || 0) * 12;
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

// In-Memory Cache with Stale-While-Revalidate (SWR) & In-Flight Coalescing
const cache = new Map();
const coalescedQueries = new Map();
const activeRevalidations = new Set();

const stats = {
  totalQueries: 0,
  cacheHits: 0,
  cacheMisses: 0,
  swrHits: 0,
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
  if (recentQueries.length > 30) recentQueries.pop();
}

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

// Robust Request Body Extractor (Handles Buffer, String, Object, and Stream safely)
async function getRequestBody(req) {
  if (req.body) {
    if (Buffer.isBuffer(req.body) && req.body.length > 0) return req.body;
    if (typeof req.body === 'string' && req.body.length > 0) return Buffer.from(req.body, 'binary');
    if (typeof req.body === 'object' && req.body !== null) {
      if (req.body.type === 'Buffer' && Array.isArray(req.body.data) && req.body.data.length > 0) {
        return Buffer.from(req.body.data);
      }
      // If req.body is non-empty object, use it; if empty {} from bodyParser, fall through to stream
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
    const timer = setTimeout(finish, 1800);
    if (timer.unref) timer.unref();
  });
}

// Query single DoH upstream with keep-alive HTTPS connection and AbortSignal support
function queryDoHUpstream(upstream, queryBuffer, timeoutMs = 2000, signal = null) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) {
      return reject(new Error('Aborted'));
    }
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
        'User-Agent': 'Antigravity-DoH/3.0'
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

    if (signal) {
      signal.addEventListener('abort', () => {
        req.destroy();
        reject(new Error('Aborted'));
      }, { once: true });
    }

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Timeout (${timeoutMs}ms) from ${upstream.name}`));
    });

    req.write(queryBuffer);
    req.end();
  });
}

// Smart Selection of Racing Candidates:
// Dynamically balances fast latency with concurrency spread so no server is bottlenecked
function selectRacingCandidates(count = 3) {
  const healthy = upstreamStates.filter(s => s.status !== 'Offline');
  if (healthy.length <= count) {
    return [...healthy];
  }

  const pool = healthy.map(c => {
    const scoreVal = Math.max(1, calculateScore(c));
    // Soft fairness bonus: slightly encourages underutilized servers while strongly prioritizing low latency
    const fairnessBonus = 1.0 + Math.max(0, 0.6 - (c.routedQueries || 0) * 0.04);
    const weight = Math.max(0.1, Math.pow(100 / scoreVal, 1.3) * fairnessBonus);
    return { candidate: c, weight };
  });

  const selected = [];
  const available = [...pool];

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

// Hedged Racing Engine with Loser Cancellation & Dual-Sided Circuit Breaker
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
          // Success telemetry for this upstream
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
          if (err.message !== 'Aborted') {
            upstream.realErrorsCount = (upstream.realErrorsCount || 0) + 1;
            upstream.penalty = Math.min(600, (upstream.penalty || 0) + 80);
            upstream.consecutiveErrors = (upstream.consecutiveErrors || 0) + 1;
            if (upstream.consecutiveErrors >= 3) upstream.status = 'Degraded';
            if (upstream.consecutiveErrors >= 5) upstream.status = 'Offline';
          }
          throw err;
        })
    );

    const winnerRes = await Promise.any(racePromises);

    // Immediately abort losing requests to free network sockets & CPU!
    abortController.abort();

    const winner = winnerRes.upstream;
    const responseBuffer = Buffer.from(winnerRes.buffer);
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

    // Fallback candidate if all candidates in race failed
    const fallbackCandidate = upstreamStates.find(u => u.status === 'Healthy' && (u.name.includes('Google') || u.name.includes('Cloudflare'))) || upstreamStates[0];
    try {
      const fbRes = await queryDoHUpstream(fallbackCandidate, queryBuffer, 2000);
      const resBuf = Buffer.from(fbRes.buffer);
      resBuf.writeUInt16BE(originalTxId, 0);
      fallbackCandidate.routedQueries = (fallbackCandidate.routedQueries || 0) + 1;
      return {
        responseBuffer: resBuf,
        from: fallbackCandidate.name,
        winner: fallbackCandidate
      };
    } catch (fbErr) {
      throw new Error(`All upstreams timed out (${err.message})`);
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

// Core DoH Handler with In-Memory Caching & SWR
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
      'Resolved'
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

    return responseBuffer;
  } catch (err) {
    stats.errors++;
    const q0 = dnsQueryObj.questions && dnsQueryObj.questions[0];
    recordRecentQuery(q0 ? q0.name : 'query', q0 ? q0.type : 'A', 'Thất bại', '-', Date.now() - startTime, 'SERVFAIL');

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
// DEDICATED REQUEST HANDLERS (No HTML leaks to DNS clients)
// -------------------------------------------------------------

// DoH Request Handler (RFC 8484 compliant)
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
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Failed to read request body');
      return;
    }

    if (!queryBuffer || queryBuffer.length < 12) {
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
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('DNS Error: ' + err.message);
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
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Invalid base64url DNS query: ' + err.message);
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
        res.writeHead(500, { 'Content-Type': 'application/json' });
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
        iosProfile: `https://${host}/profile.mobileconfig`
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

// Stats Handler
function handleStatsRequest(req, res) {
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(JSON.stringify({
    totalQueries: stats.totalQueries,
    cacheHits: stats.cacheHits,
    cacheMisses: stats.cacheMisses,
    swrHits: stats.swrHits,
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
    recentQueries: recentQueries
  }, null, 2));
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
        ttl: a.ttl || 300,
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
      domain: name,
      type,
      error: err.message
    }));
  }
}

// Apple iOS / macOS Encrypted DNS Profile (.mobileconfig)
function generateMobileConfig(host = 'localhost:3000') {
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
                <string>https://${host}/dns-query</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Cau hinh DNS over HTTPS bao mat va toc do cao</string>
            <key>PayloadDisplayName</key>
            <string>Antigravity DoH (${host})</string>
            <key>PayloadIdentifier</key>
            <string>com.antigravity.doh.${host.replace(/[^a-zA-Z0-9]/g, '.')}</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>8f12a14e-4e4b-4b2a-9285-d72b2204bc99</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Cau hinh tu dong ma hoa toan bo truy van DNS cho iPhone va Mac</string>
    <key>PayloadDisplayName</key>
    <string>Antigravity DoH - ${host}</string>
    <key>PayloadIdentifier</key>
    <string>com.antigravity.profile.${host.replace(/[^a-zA-Z0-9]/g, '.')}</string>
    <key>PayloadOrganization</key>
    <string>Antigravity Network</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>3b2f568a-c60a-4fa8-b21a-6d6545cf1888</string>
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
    'Cache-Control': 'no-cache'
  });
  res.end(xml);
}

// Modern Web Dashboard UI (Pure CSS & Vanilla JS, Fast & Responsive)
function renderDashboardHtml(req) {
  const host = req.headers.host || 'localhost:3000';
  const dohUrl = `https://${host}/dns-query`;
  const mobileConfigUrl = `https://${host}/profile.mobileconfig`;

  return `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Antigravity DoH — DNS over HTTPS Proxy</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220%22><text y=%2226%22 font-size=%2226%22>⚡</text></svg>">
    <style>
        :root {
            --primary: #38bdf8;
            --primary-dark: #0284c7;
            --accent: #818cf8;
            --surface-bg: #0b0f19;
            --surface-card: #111827;
            --surface-border: #1f293d;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --color-healthy: #10b981;
            --color-warning: #f59e0b;
            --color-danger: #ef4444;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--surface-bg);
            color: var(--text-main);
            line-height: 1.5;
            padding: 20px;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        /* Header */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--surface-card);
            border: 1px solid var(--surface-border);
            padding: 20px 24px;
            border-radius: 16px;
            flex-wrap: wrap;
            gap: 15px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .brand-icon {
            font-size: 2.2rem;
            background: linear-gradient(135deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-text h1 {
            font-size: 1.45rem;
            font-weight: 800;
            letter-spacing: -0.02em;
        }

        .brand-text p {
            font-size: 0.85rem;
            color: var(--text-muted);
        }

        .badge-live {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.1);
            color: var(--color-healthy);
            border: 1px solid rgba(16, 185, 129, 0.25);
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 0.82rem;
            font-weight: 600;
        }

        .pulse-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--color-healthy);
            box-shadow: 0 0 10px var(--color-healthy);
        }

        /* iOS Hero Card */
        .ios-banner {
            background: linear-gradient(135deg, #1e1b4b 0%, #172554 100%);
            border: 1px solid #4338ca;
            border-radius: 16px;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .ios-banner-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }

        .ios-banner-title {
            font-size: 1.25rem;
            font-weight: 700;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .btn-ios {
            background: #38bdf8;
            color: #0b0f19;
            font-weight: 700;
            font-size: 0.95rem;
            padding: 12px 22px;
            border-radius: 10px;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
            box-shadow: 0 4px 14px rgba(56, 189, 248, 0.35);
        }

        .btn-ios:hover {
            background: #7dd3fc;
            transform: translateY(-1px);
        }

        .steps-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 14px;
        }

        .step-item {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 14px;
            font-size: 0.88rem;
            color: #cbd5e1;
        }

        .step-item strong {
            display: block;
            color: #fff;
            margin-bottom: 4px;
        }

        /* URL Card */
        .url-card {
            background: var(--surface-card);
            border: 1px solid var(--surface-border);
            border-radius: 16px;
            padding: 20px 24px;
            display: flex;
            flex-direction: column;
            gap: 14px;
        }

        .url-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .url-card-header h2 {
            font-size: 1.15rem;
            font-weight: 700;
            color: #fff;
        }

        .url-box {
            background: #080c14;
            border: 1px solid #1e293b;
            border-radius: 10px;
            padding: 14px 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
            font-family: monospace;
            font-size: 1.05rem;
            color: var(--primary);
            overflow-x: auto;
        }

        .btn-copy {
            background: rgba(56, 189, 248, 0.15);
            border: 1px solid rgba(56, 189, 248, 0.3);
            color: var(--primary);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.85rem;
            white-space: nowrap;
            transition: all 0.2s;
        }

        .btn-copy:hover {
            background: var(--primary);
            color: #000;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
        }

        .stat-card {
            background: var(--surface-card);
            border: 1px solid var(--surface-border);
            border-radius: 14px;
            padding: 18px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .stat-label {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }

        .stat-value {
            font-size: 1.7rem;
            font-weight: 800;
            color: #fff;
        }

        .stat-unit {
            font-size: 0.9rem;
            color: var(--text-muted);
            font-weight: normal;
            margin-left: 4px;
        }

        /* Main Panels */
        .main-panel {
            background: var(--surface-card);
            border: 1px solid var(--surface-border);
            border-radius: 16px;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 18px;
        }

        .main-panel h2 {
            font-size: 1.25rem;
            font-weight: 700;
            color: #fff;
        }

        /* Tester Component */
        .tester-bar {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .tester-input {
            flex: 1;
            min-width: 200px;
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
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }

        th {
            padding: 12px 14px;
            border-bottom: 2px solid var(--surface-border);
            color: var(--text-muted);
            font-weight: 600;
        }

        td {
            padding: 12px 14px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            color: var(--text-main);
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
                    <p>Máy chủ DNS-over-HTTPS tốc độ cao — Chia tải thông minh nhạy trễ</p>
                </div>
            </div>
            <div class="badge-live">
                <div class="pulse-dot"></div>
                Vercel Serverless Ready
            </div>
        </header>

        <!-- 1-Click iOS Quick Install Profile -->
        <div class="ios-banner">
            <div class="ios-banner-header">
                <div class="ios-banner-title">
                    <span>📱</span>
                    <span>Cài đặt 1-chạm cho iPhone, iPad & Mac (Khắc phục 100% lỗi mạng)</span>
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
                    Bấm <em>Cài đặt</em> ở góc phải trên. Hoàn tất! Toàn bộ máy sẽ tự động sử dụng DoH bảo mật, không cần cài bất kỳ ứng dụng nào.
                </div>
            </div>
        </div>

        <!-- URL Configuration Card -->
        <div class="url-card">
            <div class="url-card-header">
                <h2>🌐 Địa chỉ DoH RFC 8484 (Cài đặt thủ công)</h2>
                <span style="font-size: 0.85rem; color: var(--text-muted);">Hỗ trợ GET / POST RFC 8484 & JSON</span>
            </div>
            <div class="url-box">
                <span id="doh-url">${dohUrl}</span>
                <button class="btn-copy" onclick="copyUrl('doh-url')">Sao chép</button>
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
                <span class="stat-label">Tỷ lệ Trúng Cache (RAM)</span>
                <span class="stat-value" id="cache-hit-rate">0<span class="stat-unit">%</span></span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Trúng Bộ Đệm SWR</span>
                <span class="stat-value" id="swr-hits">0</span>
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
            <div id="test-result-box" class="test-result-box">
                <div id="test-result-meta" style="color: var(--primary); margin-bottom: 8px; font-weight: 600;"></div>
                <div id="test-result-pre"></div>
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
        function copyUrl(elementId) {
            const text = document.getElementById(elementId).innerText;
            navigator.clipboard.writeText(text).then(() => {
                alert('Đã sao chép URL: ' + text);
            }).catch(() => {
                prompt('Sao chép đường dẫn này:', text);
            });
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
                document.getElementById('pool-size').innerHTML = (data.poolSize || 3) + '<span class="stat-unit">máy chủ</span>';

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
        setInterval(fetchStats, 4000);
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

  // 4. Test DoH
  if (pathname === '/api/test-doh') {
    return handleTestDoHRequest(req, res);
  }

  // 5. Apple iOS/macOS Encrypted DNS Profile (.mobileconfig)
  if (pathname === '/profile.mobileconfig' || pathname === '/api/profile') {
    return handleProfileRequest(req, res);
  }

  // 6. Default: Serve Web Dashboard
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

// Periodic canary health probe for Degraded/Offline upstreams (every 30 seconds)
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
      const res = await queryDoHUpstream(u, probeQuery, 2000);
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
}, 30000);
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
  handleTestDoHRequest,
  handleProfileRequest,
  generateMobileConfig,
  handleDoH
};
module.exports.default = handler;
