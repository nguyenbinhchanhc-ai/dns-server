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
  swrHits: 0,            // Stale-While-Revalidate hits (0ms latency to client)
  cacheMisses: 0,
  errors: 0,
  totalLatency: 0,
  averageLatency: 0
};

// Upstream Performance & Health Registry
const upstreamStates = UPSTREAMS.map(dns => ({
  ip: dns.ip,
  name: dns.name,
  pings: [],              // Last 5 ping latencies
  successCount: 0,
  failCount: 0,
  avgLatency: 120,
  lossRate: 0,
  
  realAvgLatency: 0,      // Exponential Moving Average (EMA) of real queries
  realQueriesCount: 0,
  realErrorsCount: 0,
  
  penalty: 0,             // Active penalty (ms) for errors, decays over time
  score: 120,             // Score = avgLatency + lossRate*5 + penalty
  routedQueries: 0,       // Total client queries won by this upstream
  status: 'Healthy'
}));

// Pre-sorted active candidates & dynamic pool size
let activeCandidates = [];
let currentPoolSize = 2;

function updateCandidates() {
  const sorted = [...upstreamStates]
    .filter(s => s.status !== 'Offline')
    .sort((a, b) => a.score - b.score);
    
  if (sorted.length === 0) {
    activeCandidates = upstreamStates.slice(0, 2);
    currentPoolSize = 2;
    return;
  }

  // Jitter & Quality Aware Dynamic Racing Pool Sizing (2 to 4 servers)
  let poolSize = 2;

  if (sorted.length >= 3) {
    const gap1to2 = sorted[1].avgLatency - sorted[0].avgLatency;
    const gap1to3 = sorted[2].avgLatency - sorted[0].avgLatency;
    
    if (gap1to3 < 20 || gap1to2 < 12) {
      poolSize = 3;
    }
    if (sorted[0].lossRate > 0 || sorted[1].lossRate > 0 || sorted[2].lossRate > 0) {
      poolSize = 3;
    }
  }

  if (sorted.length >= 4) {
    const gap1to4 = sorted[3].avgLatency - sorted[0].avgLatency;
    const hasWarning = sorted.slice(0, 3).some(s => s.status === 'Warning');
    
    if (hasWarning || gap1to4 < 15) {
      poolSize = 4;
    }
  }

  poolSize = Math.max(2, Math.min(poolSize, sorted.length));
  currentPoolSize = poolSize;
  activeCandidates = sorted; // Expand to all active candidates to allow 10 DNS servers load sharing
}

// AI Operations Activity Log (Neon-themed Web UI log)
const aiActivities = [];

function logAiActivity(type, message) {
  const d = new Date();
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  const timeStr = `${h}:${m}:${s}`;

  aiActivities.unshift({
    time: timeStr,
    type,
    message
  });
  if (aiActivities.length > 15) aiActivities.pop();
}

// Domain-Specific DNS Latency records (domain -> Map(dnsIp -> latency))
const domainDnsLatency = new Map();
let lastRouterLogTime = 0;

// Dynamic Latency-Sensitive Weighting + Domain-Peering AI Routing
// Selects best upstream based on global stats, adjusted by domain-specific historical latency
function selectWeightedUpstream(candidates, domain) {
  if (!candidates || candidates.length === 0) return null;
  if (candidates.length === 1) return candidates[0];

  const domainMap = domain ? domainDnsLatency.get(domain) : null;
  let loggedRouter = false;

  const weights = candidates.map(c => {
    let score = c.score;
    
    // AI Domain-Peering Tuning: Blend global score with historical domain-specific latency (50-50 weight)
    if (domainMap && domainMap.has(c.ip)) {
      const histLat = domainMap.get(c.ip);
      score = Math.round(0.5 * score + 0.5 * (histLat + c.lossRate * 5 + c.penalty));
      
      const now = Date.now();
      if (now - lastRouterLogTime > 4000 && !loggedRouter) {
        const dnsName = c.name;
        setImmediate(() => {
          logAiActivity('ROUTER', `Định tuyến AI: ${domain} ➔ ${dnsName} (Tối ưu lịch sử: ${histLat}ms)`);
        });
        lastRouterLogTime = now;
        loggedRouter = true;
      }
    }
    
    const scoreVal = Math.max(1, score);
    return {
      candidate: c,
      value: Math.pow(1000 / scoreVal, 1.5)
    };
  });

  const totalWeight = weights.reduce((sum, w) => sum + w.value, 0);
  if (totalWeight <= 0) return candidates[0];

  let rand = Math.random() * totalWeight;
  for (const w of weights) {
    rand -= w.value;
    if (rand <= 0) {
      return w.candidate;
    }
  }
  return candidates[0];
}

// In-Memory DNS Cache (Key: name:type:class)
const cache = new Map();

// Active background revalidations to prevent duplicate requests
const activeRevalidations = new Set();

// Active Pending Upstream Queries (UDP mapping)
const pendingQueries = new Map();
let nextTxId = 1;

// Initialize a pool of 5 outgoing UDP sockets to prevent I/O bottlenecks under load
const SOCKET_POOL_SIZE = 5;
const socketPool = [];
let nextSocketIndex = 0;

function handleIncomingUDP(msg, rinfo) {
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
}

for (let i = 0; i < SOCKET_POOL_SIZE; i++) {
  const sock = dgram.createSocket('udp4');
  
  sock.on('message', (msg, rinfo) => {
    handleIncomingUDP(msg, rinfo);
  });
  
  sock.on('error', (err) => {
    console.error(`UDP socket pool [${i}] error:`, err);
  });
  
  sock.bind(0, () => {
    try {
      sock.setRecvBufferSize(1024 * 1024);
      sock.setSendBufferSize(1024 * 1024);
    } catch (err) {
      console.warn(`Could not set buffer size on socket [${i}]:`, err.message);
    }
  });
  
  socketPool.push(sock);
}

function getSocketFromPool() {
  const sock = socketPool[nextSocketIndex];
  nextSocketIndex = (nextSocketIndex + 1) % SOCKET_POOL_SIZE;
  return sock;
}

// Unique transaction ID generator
function getNextTxId() {
  let id = nextTxId;
  while (pendingQueries.has(id)) {
    id = (id + 1) % 65536;
  }
  nextTxId = (id + 1) % 65536;
  return id;
}

// Active Health Check: Ping an upstream with a standard, universally supported A-record query for google.com
function pingUpstream(ip) {
  return new Promise((resolve) => {
    const txId = getNextTxId();
    
    const pingPacket = dnsPacket.encode({
      type: 'query',
      id: txId,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: 'A',
        name: 'google.com'
      }]
    });

    const startTime = Date.now();
    const timeout = setTimeout(() => {
      pendingQueries.delete(txId);
      resolve({ success: false, latency: 1000 });
    }, 1500);

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

    getSocketFromPool().send(pingPacket, 0, pingPacket.length, 53, ip, (err) => {
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
    
    if (res.success) {
      state.pings.push(res.latency);
      state.successCount++;
    } else {
      state.pings.push(1000);
      state.failCount++;
    }
    if (state.pings.length > 5) {
      state.pings.shift();
    }

    const validPings = state.pings.filter(p => p !== 1000);
    state.avgLatency = validPings.length > 0 
      ? Math.round(validPings.reduce((a, b) => a + b, 0) / validPings.length)
      : 1000;

    const lostCount = state.pings.filter(p => p === 1000).length;
    state.lossRate = Math.round((lostCount / state.pings.length) * 100);

    state.penalty = Math.max(0, Math.round(state.penalty * 0.5));

    state.score = state.avgLatency + (state.lossRate * 5) + state.penalty;

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

performHealthChecks().then(() => {
  updateCandidates();
});
setInterval(performHealthChecks, 25000);
setInterval(updateCandidates, 5000); // Update rankings every 5s to keep CPU low

// Perform DNS routing using Dynamic Weighted Load Balancing + Speculative Backup Retry (Dynamic delay)
function raceDNS(queryBuffer, timeoutMs = 1200, domain) {
  return new Promise((resolve, reject) => {
    const candidates = activeCandidates;
    if (candidates.length === 0) {
      reject(new Error('No active DNS candidates'));
      return;
    }

    const sock = getSocketFromPool(); // Pick a socket from pool for this query
    const originalTxId = queryBuffer.readUInt16BE(0);
    const myTxId = getNextTxId();

    const upstreamQuery = Buffer.from(queryBuffer);
    upstreamQuery.writeUInt16BE(myTxId, 0);

    const startTime = Date.now();

    // Select primary dynamically by weights and domain-peering AI
    const primary = selectWeightedUpstream(candidates, domain);
    let backupStarted = false;
    let backupTimer = null;

    const timeout = setTimeout(() => {
      pendingQueries.delete(myTxId);
      if (backupTimer) clearTimeout(backupTimer);

      const queried = backupStarted ? candidates : [primary];
      queried.forEach(state => {
        state.realErrorsCount++;
        state.penalty = Math.min(1000, state.penalty + 250);
        state.score = state.avgLatency + (state.lossRate * 5) + state.penalty;
      });

      reject(new Error('DNS query timeout'));
    }, timeoutMs);

    pendingQueries.set(myTxId, {
      resolve: ({ buffer, from }) => {
        clearTimeout(timeout);
        if (backupTimer) clearTimeout(backupTimer);
        const latency = Date.now() - startTime;
        
        const responseBuffer = Buffer.from(buffer);
        responseBuffer.writeUInt16BE(originalTxId, 0);
        
        const winner = upstreamStates.find(s => s.ip === from);
        if (winner) {
          winner.routedQueries++;
          
          const alpha = 0.3;
          winner.realAvgLatency = winner.realQueriesCount === 0 
            ? latency 
            : Math.round(alpha * latency + (1 - alpha) * winner.realAvgLatency);
          winner.realQueriesCount++;
          
          winner.penalty = Math.max(0, winner.penalty - 25);
          winner.score = winner.avgLatency + (winner.lossRate * 5) + winner.penalty;
        }

        resolve({ responseBuffer, from });
      },
      reject: (err) => {
        clearTimeout(timeout);
        if (backupTimer) clearTimeout(backupTimer);
        pendingQueries.delete(myTxId);
        
        const queried = backupStarted ? candidates : [primary];
        queried.forEach(state => {
          state.realErrorsCount++;
          state.penalty = Math.min(1000, state.penalty + 200);
          state.score = state.avgLatency + (state.lossRate * 5) + state.penalty;
        });

        reject(err);
      },
      timeout
    });

    // Send query to primary
    sock.send(upstreamQuery, 0, upstreamQuery.length, 53, primary.ip, (err) => {
      if (err) {
        if (backupTimer) clearTimeout(backupTimer);
        triggerBackup();
      }
    });

    // Dynamic Speculative Backup Delay: wait only 1.4x of primary's latency (min 70ms, max 250ms)
    const backupDelay = Math.max(70, Math.min(250, Math.round(primary.avgLatency * 1.4)));
    
    backupTimer = setTimeout(() => {
      triggerBackup();
    }, backupDelay);

    function triggerBackup() {
      if (backupStarted) return;
      backupStarted = true;

      // Send query to the top 2 fastest backup candidates (excluding the primary)
      let sentCount = 0;
      for (const state of candidates) {
        if (state.ip !== primary.ip && sentCount < 2) {
          sock.send(upstreamQuery, 0, upstreamQuery.length, 53, state.ip, (err) => {
            if (err) {
              state.realErrorsCount++;
              state.penalty = Math.min(1000, state.penalty + 100);
              state.score = state.avgLatency + (state.lossRate * 5) + state.penalty;
            }
          });
          sentCount++;
        }
      }
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

  if (minTtl < 60) minTtl = 60; // Enforce minimum TTL of 60 seconds
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

// Lightweight AI Markov Chain Behavior Predictor for DNS Prefetching
const transitionModel = new Map(); // domainA -> Map(domainB -> count)
let lastDomainName = null;
let lastDomainTime = 0;

function recordTransition(prev, current) {
  if (!prev || !current || prev === current) return;
  
  let nextMap = transitionModel.get(prev);
  if (!nextMap) {
    nextMap = new Map();
    transitionModel.set(prev, nextMap);
  }
  
  const count = nextMap.get(current) || 0;
  nextMap.set(current, count + 1);
  
  if (count + 1 === 3) {
    logAiActivity('LEARNER', `Liên kết chuỗi lướt web: ${prev} ➔ ${current}`);
  }
  
  // Keep memory bounded: limit next list to 5 items max per node
  if (nextMap.size > 5) {
    let lowestKey = null;
    let lowestVal = Infinity;
    for (const [k, v] of nextMap.entries()) {
      if (v < lowestVal) {
        lowestVal = v;
        lowestKey = k;
      }
    }
    if (lowestKey) nextMap.delete(lowestKey);
  }
}

function predictAndPrefetch(currentDomain) {
  const nextMap = transitionModel.get(currentDomain);
  if (!nextMap) return;
  
  // Find top predictions
  const sortedNext = [...nextMap.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 2); // Prefetch top 2 domains
    
  for (const [nextDomain, count] of sortedNext) {
    if (count >= 3) { // Proactive threshold: 3 hits
      const cacheKey = `${nextDomain}:1:IN`; // A-record cache key
      if (!cache.has(cacheKey) && !activeRevalidations.has(cacheKey)) {
        activeRevalidations.add(cacheKey);
        
        logAiActivity('PREFETCH', `Tải ngầm dự phòng: ${nextDomain} (Dự đoán từ ${currentDomain})`);
        
        const prefetchPacket = dnsPacket.encode({
          type: 'query',
          id: Math.floor(Math.random() * 65535),
          flags: dnsPacket.RECURSION_DESIRED,
          questions: [{
            type: 'A',
            name: nextDomain
          }]
        });
        
        // Pass nextDomain to raceDNS for domain-peering routing
        raceDNS(prefetchPacket, 1200, nextDomain)
          .then(({ responseBuffer, from }) => {
            try {
              const dnsRespObj = dnsPacket.decode(responseBuffer);
              const ttl = getMinTTL(dnsRespObj);
              
              const isNxDomain = dnsRespObj.rcode === 'NXDOMAIN';
              const cacheTtl = isNxDomain ? 30 : ttl;

              cache.set(cacheKey, {
                buffer: responseBuffer,
                cachedAt: Date.now(),
                originalTtl: cacheTtl,
                expiresAt: Date.now() + cacheTtl * 1000
              });

              const provider = upstreamStates.find(s => s.ip === from);
              const savedMs = provider ? provider.avgLatency : 45;
              logAiActivity('CACHE', `Làm nóng cache thành công: ${nextDomain} (Lưu từ ${provider ? provider.name : 'DNS'} | Tiết kiệm ~${savedMs}ms)`);
            } catch (e) {}
          })
          .catch(() => {})
          .finally(() => {
            activeRevalidations.delete(cacheKey);
          });
      }
    }
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

  const domain = dnsQueryObj.questions && dnsQueryObj.questions.length > 0
    ? dnsQueryObj.questions[0].name.toLowerCase()
    : null;

  // Lightweight AI Behavior Predictor: defer learning and prefetching asynchronously via setImmediate
  if (domain) {
    setImmediate(() => {
      try {
        const now = Date.now();
        if (lastDomainName && (now - lastDomainTime < 5000)) {
          recordTransition(lastDomainName, domain);
        }
        lastDomainName = domain;
        lastDomainTime = now;
        
        predictAndPrefetch(domain);
      } catch (e) {
        // Silently catch to avoid crashing critical path
      }
    });
  }

  // EDNS Client Subnet (ECS) Routing: Inject client's real public IP prefix to allow upstreams/CDNs 
  // to route the client to the closest local edge servers (Viettel, FPT, VNPT caches inside Vietnam)
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

      // Check if CLIENT_SUBNET option already exists
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
    } catch (e) {
      // Catch silently to avoid crash on malformed query buffers
    }
  }

  const cacheKey = getCacheKey(dnsQueryObj);

  // 1. Cache Lookup with SWR (Stale-While-Revalidate)
  if (cacheKey) {
    const cachedEntry = cache.get(cacheKey);
    if (cachedEntry) {
      const ageSec = (Date.now() - cachedEntry.cachedAt) / 1000;
      
      if (ageSec < cachedEntry.originalTtl) {
        // Cache is still valid!
        const clientTxId = queryBuffer.readUInt16BE(0);
        const responseBuffer = Buffer.from(cachedEntry.buffer);
        responseBuffer.writeUInt16BE(clientTxId, 0);

        // Check SWR Condition: >70% of TTL consumed OR <15s remaining
        const remainingTtl = cachedEntry.originalTtl - ageSec;
        const shouldRevalidate = (ageSec > cachedEntry.originalTtl * 0.7) || (remainingTtl < 15);

        if (shouldRevalidate && !activeRevalidations.has(cacheKey)) {
          stats.swrHits++;
          activeRevalidations.add(cacheKey); // Deduplicate background revalidations to prevent congestion
          
          // Trigger asynchronous background revalidation
          setTimeout(() => {
            raceDNS(queryBuffer, 1200, domain)
              .then(({ responseBuffer }) => {
                try {
                  const dnsRespObj = dnsPacket.decode(responseBuffer);
                  const ttl = getMinTTL(dnsRespObj);
                  
                  const isNxDomain = dnsRespObj.rcode === 'NXDOMAIN';
                  const cacheTtl = isNxDomain ? 30 : ttl;

                  cache.set(cacheKey, {
                    buffer: responseBuffer,
                    cachedAt: Date.now(),
                    originalTtl: cacheTtl,
                    expiresAt: Date.now() + cacheTtl * 1000
                  });
                } catch (e) {
                  // Ignore parse error in background revalidation
                }
              })
              .catch(() => {
                // Ignore query failures in background
              })
              .finally(() => {
                activeRevalidations.delete(cacheKey); // Release lock
              });
          }, 0);
        } else {
          stats.cacheHits++;
        }

        const latency = Date.now() - startTime;
        stats.totalLatency += latency;
        stats.averageLatency = stats.totalLatency / stats.totalQueries;

        return responseBuffer;
      } else {
        cache.delete(cacheKey);
      }
    }
  }

  // 2. Cache Miss: Run Upstream Race
  stats.cacheMisses++;
  try {
    const { responseBuffer, from } = await raceDNS(queryBuffer, 1200, domain);
    const latency = Date.now() - startTime;
    stats.totalLatency += latency;
    stats.averageLatency = stats.totalLatency / stats.totalQueries;

    // AI Domain-Peering: update specific domain latency mapping for the winning DNS
    if (from && domain) {
      let domainMap = domainDnsLatency.get(domain);
      if (!domainMap) {
        domainMap = new Map();
        domainDnsLatency.set(domain, domainMap);
      }
      const currentEma = domainMap.get(from) || latency;
      domainMap.set(from, Math.round(0.3 * latency + 0.7 * currentEma));
    }

    // Cache response (success or NXDOMAIN negative caching)
    if (cacheKey) {
      try {
        const dnsRespObj = dnsPacket.decode(responseBuffer);
        const ttl = getMinTTL(dnsRespObj);
        
        const isNxDomain = dnsRespObj.rcode === 'NXDOMAIN';
        const cacheTtl = isNxDomain ? 30 : ttl; // Cache NXDOMAIN for 30 seconds

        cache.set(cacheKey, {
          buffer: responseBuffer,
          cachedAt: Date.now(),
          originalTtl: cacheTtl,
          expiresAt: Date.now() + cacheTtl * 1000
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
        flags: dnsPacket.AUTHORITATIVE_ANSWER | 2,
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
    const clientIp = req.headers['x-forwarded-for']
      ? req.headers['x-forwarded-for'].split(',')[0].trim()
      : req.socket.remoteAddress;

    if (req.method === 'GET') {
      const dnsParam = parsedUrl.searchParams.get('dns');
      if (!dnsParam) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Missing dns parameter');
        return;
      }
      try {
        const queryBuffer = base64urlDecode(dnsParam);
        const responseBuffer = await handleDoH(queryBuffer, clientIp);
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
          const responseBuffer = await handleDoH(queryBuffer, clientIp);
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

  // Endpoint 1.5: AI Chat Proxy Handler
  if (parsedUrl.pathname === '/api/ai-chat') {
    if (req.method === 'POST') {
      let bodyChunks = [];
      req.on('data', chunk => bodyChunks.push(chunk));
      req.on('end', async () => {
        try {
          const body = JSON.parse(Buffer.concat(bodyChunks).toString());
          const { apiEndpoint, apiKey, model, messages } = body;
          
          if (!apiEndpoint) {
            res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('Thiếu apiEndpoint');
            return;
          }

          const isOfficialGemini = (apiKey && apiKey.startsWith('AIzaSy')) || apiEndpoint.includes('generativelanguage.googleapis.com');
          
          if (isOfficialGemini) {
            if (!apiKey) {
              res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
              res.end('Thiếu API Key cho Google AI Studio');
              return;
            }
            
            const reqModel = model === 'gemini' ? 'gemini-1.5-flash' : (model || 'gemini-1.5-flash');
            const targetUrl = `https://generativelanguage.googleapis.com/v1beta/models/${reqModel}:generateContent?key=${apiKey}`;
            
            const systemMessage = messages.find(m => m.role === 'system');
            const systemInstruction = systemMessage ? { parts: [{ text: systemMessage.content }] } : undefined;
            
            const chatContents = messages
              .filter(m => m.role !== 'system')
              .map(m => ({
                role: m.role === 'assistant' ? 'model' : 'user',
                parts: [{ text: m.content }]
              }));
              
            const response = await fetch(targetUrl, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                contents: chatContents,
                systemInstruction
              })
            });
            
            if (!response.ok) {
              const errText = await response.text();
              res.writeHead(response.status, { 'Content-Type': 'text/plain; charset=utf-8' });
              res.end(`Lỗi kết nối Official Gemini API: ${errText}`);
              return;
            }
            
            const resJson = await response.json();
            if (!resJson.candidates || resJson.candidates.length === 0 || !resJson.candidates[0].content) {
              res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
              res.end('Phản hồi trống từ Google API. Hãy kiểm tra lại API Key hoặc tên model.');
              return;
            }
            
            const replyText = resJson.candidates[0].content.parts[0].text;
            const mappedResponse = {
              choices: [
                {
                  message: {
                    role: 'assistant',
                    content: replyText
                  }
                }
              ]
            };
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify(mappedResponse));
            return;
          }
          
          const cleanEndpoint = apiEndpoint.endsWith('/') ? apiEndpoint.slice(0, -1) : apiEndpoint;
          
          let targetUrl;
          const isGeminiWebToApi = cleanEndpoint.includes('onrender.com') || cleanEndpoint.includes('localhost:4981') || cleanEndpoint.includes('127.0.0.1:4981');
          
          if (isGeminiWebToApi && !cleanEndpoint.includes('/openai')) {
            const baseHost = cleanEndpoint.endsWith('/v1') ? cleanEndpoint.slice(0, -3) : cleanEndpoint;
            targetUrl = `${baseHost}/openai/v1/chat/completions`;
          } else {
            targetUrl = cleanEndpoint.endsWith('/chat/completions') ? cleanEndpoint : `${cleanEndpoint}/chat/completions`;
          }
          
          const headers = {
            'Content-Type': 'application/json'
          };
          if (apiKey) {
            headers['Authorization'] = `Bearer ${apiKey}`;
          }
          
          const response = await fetch(targetUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify({
              model: model || 'gemini',
              messages
            })
          });
          
          if (!response.ok) {
            const errText = await response.text();
            res.writeHead(response.status, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end(`Lỗi kết nối Gemini API: ${errText}`);
            return;
          }
          
          const resJson = await response.json();
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify(resJson));
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end(err.message);
        }
      });
    } else {
      res.writeHead(405, { 'Content-Type': 'text/plain' });
      res.end('Method Not Allowed');
    }
    return;
  }

  // Endpoint 2: JSON API Stats (Includes detailed load balance & SWR data)
  if (parsedUrl.pathname === '/api/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ...stats,
      upstreams: upstreamStates,
      poolSize: currentPoolSize,
      cacheSize: cache.size,
      uptime: process.uptime(),
      aiActivities: aiActivities
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
    <title>Antigravity Hyper-Speed DNS</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #03050a;
            --panel-bg: rgba(8, 12, 24, 0.7);
            --border-color: rgba(255, 255, 255, 0.04);
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
                radial-gradient(circle at 15% 15%, rgba(0, 242, 254, 0.05) 0%, transparent 30%),
                radial-gradient(circle at 85% 85%, rgba(79, 172, 254, 0.05) 0%, transparent 30%);
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
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 35px;
        }

        .stat-card {
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 22px;
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
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 6px;
        }

        .stat-value {
            font-size: 1.8rem;
            font-weight: 600;
            font-variant-numeric: tabular-nums;
        }

        .stat-unit {
            font-size: 0.8rem;
            color: var(--text-muted);
            font-weight: 400;
            margin-left: 2px;
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
            box-shadow: 0 5px 15px rgba(0, 247, 255, 0.25);
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

        @keyframes pulse {
            0% { transform: scale(0.85); opacity: 0.5; }
            50% { transform: scale(1.2); opacity: 1; }
            100% { transform: scale(0.85); opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Latency Warning Banner for Singapore Region Recommendation -->
        <div id="latency-warning-banner" style="display: none; background: linear-gradient(135deg, #ff453a 0%, #ff9f0a 100%); color: #000; padding: 15px 25px; text-align: center; font-weight: 600; font-size: 0.95rem; border-radius: 12px; margin-bottom: 25px; box-shadow: 0 5px 15px rgba(255, 69, 58, 0.2); position: relative; padding-right: 45px;">
            ⚠️ CẢNH BÁO ĐỘ TRỄ CAO: Kết nối từ thiết bị của bạn đến máy chủ Render hiện tại là <span id="client-latency-val">0</span>ms (ì ạch). 
            Hãy chuyển vùng (region) của Web Service trên Render sang <strong>Singapore (SG)</strong> để tối ưu hóa RTT xuống 30-40ms!
            <button onclick="dismissBanner()" style="position: absolute; right: 15px; top: 50%; transform: translateY(-50%); background: none; border: none; font-size: 1.4rem; font-weight: bold; cursor: pointer; color: #000; opacity: 0.7; line-height: 1;">&times;</button>
        </div>

        <header>
            <h1>Antigravity Hyper-Speed DNS</h1>
            <p>Định tuyến thích ứng EMA, tối ưu hoá bộ nhớ đệm SWR & Racing Pool thông minh</p>
        </header>

        <div class="grid-stats">
            <div class="stat-card">
                <div class="stat-title">Tổng truy vấn</div>
                <div class="stat-value" id="total-queries">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Cache Hit thông thường</div>
                <div class="stat-value" id="cache-hit-rate">0<span class="stat-unit">%</span></div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Tối ưu hóa SWR (0ms)</div>
                <div class="stat-value" id="swr-hits">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Độ trễ trung bình</div>
                <div class="stat-value" id="avg-latency">0<span class="stat-unit">ms</span></div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Kích thước Racing Pool</div>
                <div class="stat-value" id="pool-size">0<span class="stat-unit">servers</span></div>
            </div>
        </div>

        <div class="main-panel">
            <h2>Bảng hiệu năng thích ứng (Adaptive DNS & Racing Leaderboard)</h2>
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

        <div class="main-panel" style="border: 1px solid rgba(139, 92, 246, 0.25); background: rgba(15, 10, 30, 0.5); box-shadow: 0 0 15px rgba(139, 92, 246, 0.05); margin-top: 10px;">
            <h2 style="color: #a78bfa; display: flex; align-items: center; gap: 10px;">
                🧠 Trợ lý Phân tích & Trò chuyện Gemini AI
            </h2>
            <p style="font-size: 0.9rem; color: var(--text-muted); margin-bottom: 20px;">
                Tích hợp bộ não AI từ dự án <a href="https://github.com/ntthanh2603/gemini-web-to-api" target="_blank" style="color: #c084fc; text-decoration: underline;">gemini-web-to-api</a> để phân tích sức khỏe mạng và trò chuyện hỗ trợ vận hành.
            </p>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; background: rgba(0,0,0,0.25); padding: 15px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05);">
                <div>
                    <label style="display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 5px; font-weight: 600;">Địa chỉ API Bộ não</label>
                    <input type="text" id="ai-endpoint" value="http://localhost:4981/v1" style="width: 100%; padding: 8px 12px; border-radius: 6px; border: 1px solid var(--border-color); background: rgba(0,0,0,0.4); color: #fff; font-size: 0.85rem;" placeholder="http://localhost:4981/v1">
                </div>
                <div>
                    <label style="display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 5px; font-weight: 600;">API Key (Nếu có)</label>
                    <input type="password" id="ai-key" style="width: 100%; padding: 8px 12px; border-radius: 6px; border: 1px solid var(--border-color); background: rgba(0,0,0,0.4); color: #fff; font-size: 0.85rem;" placeholder="Bỏ trống nếu chạy Docker local">
                </div>
                <div>
                    <label style="display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 5px; font-weight: 600;">Model sử dụng</label>
                    <input type="text" id="ai-model" value="gemini" style="width: 100%; padding: 8px 12px; border-radius: 6px; border: 1px solid var(--border-color); background: rgba(0,0,0,0.4); color: #fff; font-size: 0.85rem;" placeholder="gemini">
                </div>
            </div>

            <div style="display: flex; gap: 15px; margin-bottom: 20px;">
                <button class="btn-copy" onclick="analyzeNetwork()" style="background: rgba(139, 92, 246, 0.15); border-color: rgba(139, 92, 246, 0.3); color: #c084fc; font-weight: 600; padding: 10px 20px;">📊 AI Phân tích hiệu năng mạng</button>
            </div>

            <div id="ai-analysis-result" style="display: none; background: rgba(0,0,0,0.2); border: 1px solid rgba(139, 92, 246, 0.2); border-radius: 12px; padding: 20px; font-size: 0.9rem; line-height: 1.6; margin-bottom: 25px; max-height: 300px; overflow-y: auto; text-align: left;">
                <!-- AI insights render here -->
            </div>

            <div style="border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; overflow: hidden; background: rgba(0,0,0,0.2);">
                <div id="ai-chat-history" style="height: 250px; overflow-y: auto; padding: 15px; display: flex; flex-direction: column; gap: 12px; font-size: 0.9rem; text-align: left;">
                    <div style="color: var(--text-muted); text-align: center; margin-top: 80px;">Trò chuyện với trợ lý Gemini AI... Hỏi tôi bất cứ câu hỏi nào về hệ thống DNS này!</div>
                </div>
                <div style="display: flex; border-top: 1px solid rgba(255,255,255,0.05);">
                    <input type="text" id="ai-chat-input" style="flex: 1; padding: 15px; background: rgba(0,0,0,0.3); border: none; color: #fff; font-size: 0.9rem;" placeholder="Hỏi Gemini..." onkeydown="if(event.key === 'Enter') sendAiChat()">
                    <button onclick="sendAiChat()" style="padding: 0 25px; background: #8b5cf6; border: none; color: #fff; font-weight: 600; cursor: pointer; transition: background 0.2s;">Gửi</button>
                </div>
            </div>
        </div>

        <div class="main-panel" style="border: 1px solid rgba(0, 247, 255, 0.2); background: rgba(0, 8, 16, 0.5); box-shadow: 0 0 15px rgba(0, 247, 255, 0.05); margin-top: 10px;">
            <h2 style="color: var(--accent-glow); display: flex; align-items: center; gap: 10px;">
                <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: var(--accent-solid); box-shadow: 0 0 8px var(--accent-solid); animation: pulse 1.5s infinite;"></span>
                Nhật ký hoạt động của AI Engine (Markov Predictor & Peering Router)
            </h2>
            <div id="ai-log-container" style="max-height: 220px; overflow-y: auto; font-family: monospace; font-size: 0.85rem; padding: 15px; border-radius: 12px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.05); display: flex; flex-direction: column; gap: 8px; scroll-behavior: smooth;">
                <!-- Renders dynamically -->
            </div>
        </div>

        <footer>
            <p>Thuật toán tối ưu SWR Caching & Dynamic Jitter Racing. Phát triển bởi Antigravity Coding Engine v3.</p>
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

        function dismissBanner() {
            localStorage.setItem('hideLatencyWarning', 'true');
            document.getElementById('latency-warning-banner').style.display = 'none';
        }

        async function fetchStats() {
            const startTime = Date.now();
            try {
                const res = await fetch('/api/stats');
                const clientLatency = Date.now() - startTime;
                const data = await res.json();
                
                // Show region warning banner if device-to-server RTT is too high and not dismissed
                const banner = document.getElementById('latency-warning-banner');
                const latVal = document.getElementById('client-latency-val');
                const isDismissed = localStorage.getItem('hideLatencyWarning') === 'true';
                
                if (clientLatency > 120 && !isDismissed) {
                    banner.style.display = 'block';
                    latVal.innerText = clientLatency;
                } else {
                    banner.style.display = 'none';
                }

                document.getElementById('total-queries').innerText = data.totalQueries.toLocaleString();
                const hitRate = data.totalQueries > 0 ? Math.round((data.cacheHits / data.totalQueries) * 100) : 0;
                document.getElementById('cache-hit-rate').innerHTML = hitRate + '<span class="stat-unit">%</span>';
                document.getElementById('swr-hits').innerText = data.swrHits.toLocaleString();
                document.getElementById('avg-latency').innerHTML = Math.round(data.averageLatency) + '<span class="stat-unit">ms</span>';
                document.getElementById('pool-size').innerHTML = data.poolSize + '<span class="stat-unit">servers</span>';

                const tableBody = document.getElementById('dns-table-body');
                tableBody.innerHTML = '';

                const upstreams = data.upstreams || [];
                const totalRouted = upstreams.reduce((acc, curr) => acc + curr.routedQueries, 0);

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
                    } else if (index < data.poolSize) {
                        if (index === 0) {
                          rankText = '#1 Primary';
                          rankClass = 'rank-primary';
                        } else {
                          rankText = '#' + (index + 1) + ' Racing';
                          rankClass = 'rank-secondary';
                        }
                    }

                    const routedPercent = totalRouted > 0 ? Math.round((dns.routedQueries / totalRouted) * 100) : 0;
                    
                    let latClass = 'latency-Healthy';
                    if (dns.avgLatency > 250) latClass = 'latency-Offline';
                    else if (dns.avgLatency > 120) latClass = 'latency-Warning';

                    let realLatStr = '--';
                    if (dns.realAvgLatency > 0) {
                        realLatStr = dns.realAvgLatency + ' ms';
                    }

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

                // Render AI Operations Log
                const aiLog = document.getElementById('ai-log-container');
                aiLog.innerHTML = '';
                const activities = data.aiActivities || [];
                if (activities.length === 0) {
                    aiLog.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 20px;">AI đang phân tích và tối ưu hóa luồng dữ liệu...</div>';
                } else {
                    activities.forEach(act => {
                        let color = '#fff';
                        if (act.type === 'LEARNER') color = '#a78bfa'; // Purple
                        else if (act.type === 'PREFETCH') color = '#38bdf8'; // Blue
                        else if (act.type === 'CACHE') color = '#34d399'; // Green
                        else if (act.type === 'ROUTER') color = '#fbbf24'; // Yellow
                        
                        const div = document.createElement('div');
                        div.style.lineHeight = '1.5';
                        div.innerHTML = '<span style="color: var(--text-muted); font-variant-numeric: tabular-nums;">[' + act.time + ']</span> ' +
                            '<span style="color: ' + color + '; font-weight: bold; margin-right: 5px;">[AI ' + act.type + ']</span> ' +
                            '<span>' + act.message + '</span>';
                        aiLog.appendChild(div);
                    });
                }

            } catch (err) {
                console.error('Error loading stats:', err);
            }
        }

        // Save/Load API Configuration
        window.addEventListener('DOMContentLoaded', () => {
            const savedEndpoint = localStorage.getItem('ai_endpoint');
            const savedKey = localStorage.getItem('ai_key');
            const savedModel = localStorage.getItem('ai_model');

            if (savedEndpoint) document.getElementById('ai-endpoint').value = savedEndpoint;
            if (savedKey) document.getElementById('ai-key').value = savedKey;
            if (savedModel) document.getElementById('ai-model').value = savedModel;
        });

        function saveConfig() {
            const ep = document.getElementById('ai-endpoint').value;
            const key = document.getElementById('ai-key').value;
            const model = document.getElementById('ai-model').value;

            localStorage.setItem('ai_endpoint', ep);
            localStorage.setItem('ai_key', key);
            localStorage.setItem('ai_model', model);
            return { ep, key, model };
        }

        async function queryGemini(messages) {
            const config = saveConfig();
            
            const response = await fetch('/api/ai-chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    apiEndpoint: config.ep,
                    apiKey: config.key,
                    model: config.model,
                    messages: messages
                })
            });

            if (!response.ok) {
                const errText = await response.text();
                throw new Error(errText);
            }

            const data = await response.json();
            return data.choices[0].message.content;
        }

        let chatMessages = [];

        async function sendAiChat() {
            const input = document.getElementById('ai-chat-input');
            const query = input.value.trim();
            if (!query) return;

            input.value = '';
            
            const chatHistory = document.getElementById('ai-chat-history');
            if (chatMessages.length === 0) chatHistory.innerHTML = '';

            // Render User message
            const userDiv = document.createElement('div');
            userDiv.style.alignSelf = 'flex-end';
            userDiv.style.background = 'rgba(139, 92, 246, 0.2)';
            userDiv.style.padding = '10px 15px';
            userDiv.style.borderRadius = '12px 12px 0 12px';
            userDiv.style.maxWidth = '80%';
            userDiv.style.marginBottom = '8px';
            userDiv.innerHTML = '<strong>Bạn:</strong><br>' + escapeHtml(query);
            chatHistory.appendChild(userDiv);
            chatHistory.scrollTop = chatHistory.scrollHeight;

            chatMessages.push({ role: 'user', content: query });

            // Render AI Loading
            const aiDiv = document.createElement('div');
            aiDiv.style.alignSelf = 'flex-start';
            aiDiv.style.background = 'rgba(255, 255, 255, 0.05)';
            aiDiv.style.padding = '10px 15px';
            aiDiv.style.borderRadius = '12px 12px 12px 0';
            aiDiv.style.maxWidth = '80%';
            aiDiv.style.marginBottom = '8px';
            aiDiv.innerHTML = '<strong>Gemini:</strong><br><span style="color: var(--text-muted);">Đang suy nghĩ...</span>';
            chatHistory.appendChild(aiDiv);
            chatHistory.scrollTop = chatHistory.scrollHeight;

            try {
                const systemPrompt = 'Bạn là Trợ lý AI đặc biệt được tích hợp trong Dashboard của Antigravity DNS Proxy, phát triển dựa trên dự án gemini-web-to-api. Bạn có nhiệm vụ giải đáp thắc mắc về hệ thống DNS, mạng di động, và hướng dẫn vận hành DNS Server này cho người dùng.';
                const payload = [
                    { role: 'system', content: systemPrompt },
                    ...chatMessages
                ];
                const reply = await queryGemini(payload);
                
                aiDiv.innerHTML = '<strong>Gemini:</strong><br>' + formatMarkdown(reply);
                chatMessages.push({ role: 'assistant', content: reply });
            } catch (err) {
                aiDiv.innerHTML = '<strong>Gemini:</strong><br><span style="color: #ff453a;">Lỗi kết nối bộ não AI: ' + escapeHtml(err.message) + '</span>';
            }
            chatHistory.scrollTop = chatHistory.scrollHeight;
        }

        async function analyzeNetwork() {
            const resultBox = document.getElementById('ai-analysis-result');
            resultBox.style.display = 'block';
            resultBox.innerHTML = '<span style="color: var(--text-muted);">Đang tải dữ liệu mạng và phân tích với Gemini AI...</span>';

            try {
                const res = await fetch('/api/stats');
                const stats = await res.json();
                
                let upstreamsStr = '';
                for (let i = 0; i < stats.upstreams.length; i++) {
                    const dns = stats.upstreams[i];
                    upstreamsStr += '- ' + dns.name + ' (' + dns.ip + '): Ping ' + dns.avgLatency + 'ms, Trễ thực EMA ' + dns.realAvgLatency + 'ms, Đã chia ' + dns.routedQueries + ' truy vấn, Trạng thái: ' + dns.status + '\\n';
                }

                const prompt = 'Hãy đóng vai trò là Chuyên gia Tối ưu hóa Mạng. Phân tích các thông số hoạt động của máy chủ DNS sau đây để cung cấp một báo cáo sức khỏe ngắn gọn và gợi ý cấu hình tốt nhất bằng Tiếng Việt.\\n\\n' +
                    'Thông số hệ thống:\\n' +
                    '- Tổng số truy vấn: ' + stats.totalQueries + '\\n' +
                    '- Tỷ lệ Cache Hit: ' + (stats.totalQueries > 0 ? Math.round((stats.cacheHits / stats.totalQueries) * 100) : 0) + '%\\n' +
                    '- Số lần SWR ngầm: ' + stats.swrHits + '\\n' +
                    '- Độ trễ trung bình: ' + Math.round(stats.averageLatency) + 'ms\\n' +
                    '- Kích thước cache hiện tại: ' + stats.cacheSize + ' bản ghi\\n' +
                    '- Uptime hoạt động: ' + Math.round(stats.uptime) + ' giây\\n' +
                    '- Trạng thái 10 Upstream DNS:\\n' + upstreamsStr + '\\n' +
                    'Yêu cầu báo cáo gồm:\\n' +
                    '1. Đánh giá trạng thái tổng quan (Ví dụ: Tốt/Có nguy cơ/Chậm).\\n' +
                    '2. Phân tích các DNS Upstream nổi bật (nhà mạng nào nhanh, nhà mạng nào có lỗi).\\n' +
                    '3. Đề xuất hành động (ví dụ: cần làm gì trên thiết bị iOS/Android hoặc cài đặt lại vùng mạng).';

                const reply = await queryGemini([{ role: 'user', content: prompt }]);
                resultBox.innerHTML = '<strong>Báo cáo Phân tích từ Gemini AI:</strong><br>' + formatMarkdown(reply);
            } catch (err) {
                resultBox.innerHTML = '<span style="color: #ff453a;">Lỗi phân tích: ' + escapeHtml(err.message) + '</span><br><p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 10px;">Lưu ý: Hãy chắc chắn dự án gemini-web-to-api đang chạy tại địa chỉ cấu hình và cookie đăng nhập đã chính xác.</p>';
            }
        }

        function escapeHtml(str) {
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
        }

        function formatMarkdown(text) {
            return text
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\*(.*?)\*/g, '<em>$1</em>')
                .replace(new RegExp('\\\\x60([^\\\\x60]+)\\\\x60', 'g'), '<code style="background: rgba(255,255,255,0.1); padding: 2px 4px; border-radius: 4px;">$1</code>')
                .replace(/\\n/g, '<br>')
                .replace(/^- (.*)$/gm, '• $1');
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

server.keepAliveTimeout = 65000; // Keep HTTPS connection open for 65 seconds
server.headersTimeout = 66000;

server.listen(PORT, () => {
  console.log("Antigravity Hyper-Speed DNS Server running on http://localhost:" + PORT);
  console.log("DNS health-check active monitoring started.");
});
