const http = require('http');
const https = require('https');
const dgram = require('dgram');
const dnsPacket = require('dns-packet');

const PORT = process.env.PORT || 3000;
const isVercel = Boolean(process.env.VERCEL || process.env.NOW_REGION || process.env.AWS_LAMBDA_FUNCTION_NAME);

// Persistent, high-performance HTTPS Agent with Keep-Alive & Connection Pooling
const httpsAgent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 60000,
  maxSockets: 50,
  maxFreeSockets: 25,
  timeout: 3000,
  rejectUnauthorized: false
});

// Upstream DoH Resolvers (IP-based URLs prevent bootstrap lookup cycles)
const UPSTREAMS = [
  { name: 'Cloudflare Primary', ip: '1.1.1.1', dohUrl: 'https://1.1.1.1/dns-query' },
  { name: 'Cloudflare Secondary', ip: '1.0.0.1', dohUrl: 'https://1.0.0.1/dns-query' },
  { name: 'Google Primary', ip: '8.8.8.8', dohUrl: 'https://8.8.8.8/dns-query' },
  { name: 'Google Secondary', ip: '8.8.4.4', dohUrl: 'https://8.8.4.4/dns-query' },
  { name: 'Quad9 Primary', ip: '9.9.9.9', dohUrl: 'https://9.9.9.9/dns-query' },
  { name: 'Quad9 Secondary', ip: '149.112.112.112', dohUrl: 'https://149.112.112.112/dns-query' },
  { name: 'AdGuard Standard', ip: '94.140.14.14', dohUrl: 'https://94.140.14.14/dns-query' },
  { name: 'AdGuard Alt', ip: '94.140.15.15', dohUrl: 'https://94.140.15.15/dns-query' },
  { name: 'ControlD Free', ip: '76.76.2.0', dohUrl: 'https://76.76.2.0/dns-query' },
  { name: 'OpenDNS Primary', ip: '208.67.222.222', dohUrl: 'https://208.67.222.222/dns-query' },
  { name: 'DNS.SB Primary', ip: '45.11.45.11', dohUrl: 'https://45.11.45.11/dns-query' },
  { name: 'Mullvad Primary', ip: '194.242.2.2', dohUrl: 'https://194.242.2.2/dns-query' }
];

// Health and telemetry state per upstream
const upstreamStates = UPSTREAMS.map(u => ({
  ...u,
  avgLatency: 20,
  realAvgLatency: 20,
  penalty: 0,
  status: 'Healthy',
  consecutiveErrors: 0,
  routedQueries: 0,
  activeQueries: 0,
  realQueriesCount: 0,
  realErrorsCount: 0
}));

let currentPoolSize = 4;

function calculateScore(state) {
  const effectiveLatency = state.realAvgLatency || state.avgLatency || 25;
  const loadPenalty = (state.activeQueries || 0) * 15;
  return effectiveLatency + (state.penalty || 0) + loadPenalty;
}

function updateCandidates() {
  const healthyCount = upstreamStates.filter(s => s.status === 'Healthy').length;
  if (healthyCount < 3) {
    currentPoolSize = 3;
  } else if (healthyCount <= 4) {
    currentPoolSize = 3;
  } else {
    currentPoolSize = 4;
  }
}

// In-Memory Cache with Stale-While-Revalidate (SWR)
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
    if (Buffer.isBuffer(req.body)) return req.body;
    if (typeof req.body === 'string') return Buffer.from(req.body, 'binary');
    if (typeof req.body === 'object') {
      if (req.body.type === 'Buffer' && Array.isArray(req.body.data)) {
        return Buffer.from(req.body.data);
      }
      return Buffer.from(JSON.stringify(req.body));
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
    const timer = setTimeout(finish, 2500);
    if (timer.unref) timer.unref();
  });
}

// Query single DoH upstream with keep-alive HTTPS connection
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

// Select candidates for racing
function selectRacingCandidates(count = 3) {
  const healthy = upstreamStates.filter(s => s.status !== 'Offline');
  if (healthy.length <= count) {
    return [...healthy];
  }

  const pool = healthy.map(c => {
    const scoreVal = Math.max(1, calculateScore(c));
    const fairnessBonus = 1.0 + Math.max(0, 0.8 - (c.routedQueries || 0) * 0.05);
    const weight = Math.max(0.1, Math.pow(1000 / scoreVal, 1.2) * fairnessBonus);
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

// Hedged Racing Engine
async function raceDNS(queryBuffer, clientIp = null, timeoutMs = 1800) {
  const originalTxId = queryBuffer.readUInt16BE(0);
  const candidates = selectRacingCandidates(currentPoolSize || 3);

  candidates.forEach(c => {
    c.activeQueries = (c.activeQueries || 0) + 1;
  });

  try {
    const racePromises = candidates.map(upstream =>
      queryDoHUpstream(upstream, queryBuffer, timeoutMs)
    );

    const winnerRes = await Promise.any(racePromises);
    const winner = winnerRes.upstream;
    const responseBuffer = Buffer.from(winnerRes.buffer);
    
    responseBuffer.writeUInt16BE(originalTxId, 0);

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
      c.consecutiveErrors = (c.consecutiveErrors || 0) + 1;
      if (c.consecutiveErrors >= 3) {
        c.status = 'Degraded';
      }
    });

    const fallbackCandidate = upstreamStates.find(u => u.name.includes('Google') || u.name.includes('Cloudflare')) || upstreamStates[0];
    try {
      const fbRes = await queryDoHUpstream(fallbackCandidate, queryBuffer, 2200);
      const resBuf = Buffer.from(fbRes.buffer);
      resBuf.writeUInt16BE(originalTxId, 0);
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

  // 2. Request Coalescing
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
            <string>com.antigravity.dns.${host}</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>3B7A849F-9D45-42EB-8B7A-72534591ABCD</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>ProhibitDisablement</key>
            <false/>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>May chu DNS over HTTPS toc do cao toi uu hoa Vercel</string>
    <key>PayloadDisplayName</key>
    <string>Antigravity DoH Proxy</string>
    <key>PayloadIdentifier</key>
    <string>com.antigravity.dns.profile.${host}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>A51B7610-82E5-46D9-B101-92CD8E591234</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;
}

function handleProfileRequest(req, res) {
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000';
  const xml = generateMobileConfig(host);
  res.writeHead(200, {
    'Content-Type': 'application/x-apple-aspen-config; charset=utf-8',
    'Content-Disposition': 'attachment; filename="Antigravity-DoH.mobileconfig"',
    'Cache-Control': 'no-cache',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(xml);
}

// -------------------------------------------------------------
// WEB DASHBOARD HTML
// -------------------------------------------------------------
function renderDashboardHtml(req) {
  const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
  const dohUrl = `https://${host}/dns-query`;
  const mobileConfigUrl = `https://${host}/profile.mobileconfig`;

  return `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Antigravity Hyper-Speed DoH Proxy — Tối ưu cho Vercel</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #03050a;
            --surface-color: #0d111a;
            --surface-card: #131926;
            --surface-border: #1e293b;
            --primary: #38bdf8;
            --primary-hover: #0ea5e9;
            --accent: #818cf8;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --color-healthy: #34d399;
            --color-warning: #fbbf24;
            --color-danger: #f87171;
            --font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: var(--font-family);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 30px 15px;
        }

        .container {
            width: 100%;
            max-width: 1100px;
            display: flex;
            flex-direction: column;
            gap: 25px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--surface-border);
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .brand-icon {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, #38bdf8, #818cf8);
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 26px;
            box-shadow: 0 0 25px rgba(56, 189, 248, 0.4);
        }

        .brand-text h1 {
            font-size: 1.6rem;
            font-weight: 800;
            background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-text p {
            font-size: 0.85rem;
            color: var(--text-muted);
        }

        .badge-live {
            background: rgba(52, 211, 153, 0.12);
            color: var(--color-healthy);
            border: 1px solid rgba(52, 211, 153, 0.3);
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .pulse-dot {
            width: 8px;
            height: 8px;
            background-color: var(--color-healthy);
            border-radius: 50%;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(52, 211, 153, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(52, 211, 153, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(52, 211, 153, 0); }
        }

        /* 1-Click iOS Quick Install Banner */
        .ios-banner {
            background: linear-gradient(135deg, rgba(56, 189, 248, 0.15), rgba(129, 140, 248, 0.1));
            border: 1px solid rgba(56, 189, 248, 0.35);
            border-radius: 16px;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }

        .ios-banner-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }

        .ios-banner-title {
            font-size: 1.25rem;
            font-weight: 700;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .btn-ios {
            background: linear-gradient(135deg, #38bdf8, #6366f1);
            color: #fff;
            padding: 12px 24px;
            border-radius: 10px;
            font-weight: 700;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            font-size: 1rem;
            box-shadow: 0 4px 15px rgba(56, 189, 248, 0.35);
            transition: all 0.2s ease;
        }

        .btn-ios:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(56, 189, 248, 0.5);
        }

        .steps-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 15px;
            margin-top: 5px;
        }

        .step-item {
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 10px;
            padding: 14px;
            font-size: 0.88rem;
            color: var(--text-muted);
        }

        .step-item strong {
            color: #fff;
            display: block;
            margin-bottom: 5px;
        }

        /* URL Card */
        .url-card {
            background: var(--surface-card);
            border: 1px solid var(--surface-border);
            border-radius: 16px;
            padding: 22px;
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
                    <p>Máy chủ DNS-over-HTTPS tốc độ cao — Phân tán đa Upstream</p>
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
                <span class="stat-value" id="pool-size">4<span class="stat-unit">máy chủ</span></span>
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
                document.getElementById('pool-size').innerHTML = (data.poolSize || 4) + '<span class="stat-unit">máy chủ</span>';

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

  // 1. Detect if incoming request is a DoH request (Strictly prevents sending HTML to DNS clients)
  const isDnsContentType = (req.headers['content-type'] || '').toLowerCase().includes('application/dns-message') ||
                           (req.headers['accept'] || '').toLowerCase().includes('application/dns-message');
  const isDnsPath = pathname === '/dns-query' ||
                    pathname === '/resolve' ||
                    pathname.endsWith('/dns-query') ||
                    pathname === '/api/dns-query';
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
