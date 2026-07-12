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
  { ip: '76.76.2.0', name: 'ControlD Unfiltered' },
  
  // Vietnam Active Resolvers (Verified Reachable)
  { ip: '203.113.131.1', name: 'Viettel DNS Primary' },
  { ip: '203.162.0.11', name: 'VNPT DNS Backup' }
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
  jitter: 0,              // Standard deviation of ping latencies
  score: 120,             // Score = avgLatency + lossRate*5 + penalty
  routedQueries: 0,       // Total client queries won by this upstream
  status: 'Healthy',

  // Enterprise Load Balancing Additions
  activeQueries: 0,       // Concurrent outstanding queries
  consecutiveErrors: 0,   // For Circuit Breaker
  recoveryTime: null      // For Slow Start warmup
}));

// Unified Score Calculator
function calculateScore(state) {
  const jitterPenalty = state.jitter > 15 ? state.jitter * 2 : 0;
  const concurrencyPenalty = (state.activeQueries || 0) * 15; // 15ms penalty per outstanding query
  state.score = state.avgLatency + (state.lossRate * 5) + state.penalty + jitterPenalty + concurrencyPenalty;
  return state.score;
}

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
  activeCandidates = sorted; // Allow all healthy DNS servers to share load
}

// Helper to calculate standard deviation (jitter) of ping samples
function getJitter(samples) {
  if (samples.length < 2) return 0;
  const mean = samples.reduce((sum, v) => sum + v, 0) / samples.length;
  const variance = samples.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / samples.length;
  return Math.round(Math.sqrt(variance));
}

// Dynamic Latency-Sensitive Weighting: Selects best upstream based on scores (RTT + Loss + Penalty + Jitter + Concurrency)
function selectWeightedUpstream(candidates) {
  if (!candidates || candidates.length === 0) return null;
  if (candidates.length === 1) return candidates[0];

  const now = Date.now();
  const weights = candidates.map(c => {
    const scoreVal = Math.max(1, calculateScore(c));
    // Slow Start Warmup: If recovered recently, scale down its weight gradually over 30s
    let warmupFactor = 1.0;
    if (c.recoveryTime) {
      const timeDiff = now - c.recoveryTime;
      if (timeDiff < 30000) {
        warmupFactor = Math.max(0.1, timeDiff / 30000);
      } else {
        c.recoveryTime = null; // Warmup complete
      }
    }
    const exponent = 1.8;
    return {
      candidate: c,
      value: Math.pow(1000 / scoreVal, exponent) * warmupFactor
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

function overrideTtlInResponse(buffer) {
  try {
    const decoded = dnsPacket.decode(buffer);
    let changed = false;
    if (decoded.answers) {
      decoded.answers.forEach(ans => {
        if (ans.ttl !== undefined && ans.ttl < 600) {
          ans.ttl = 600; // Force 10 minutes cache TTL for clients
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
  if (cache.size >= 100000) { // Max 100,000 entries (leverages ~100MB of Render RAM)
    const firstKey = cache.keys().next().value;
    if (firstKey) cache.delete(firstKey);
  }
  // Intercept buffer to apply TTL boost for client responses
  if (value && value.buffer) {
    value.buffer = overrideTtlInResponse(value.buffer);
  }
  cache.set(key, value);
}

// Active background revalidations to prevent duplicate requests
const activeRevalidations = new Set();

// Request Coalescing registry to prevent query amplification under concurrent loads
const coalescedQueries = new Map();

// Active Pending Upstream Queries (UDP mapping)
const pendingQueries = new Map();
let nextTxId = 1;

// Initialize a pool of 15 outgoing UDP sockets to prevent I/O bottlenecks under concurrent load
const SOCKET_POOL_SIZE = 15;
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
    }, 600);

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

    const jitter = getJitter(validPings);
    state.jitter = jitter;
    const jitterPenalty = jitter > 15 ? jitter * 2 : 0;

    const lostCount = state.pings.filter(p => p === 1000).length;
    state.lossRate = Math.round((lostCount / state.pings.length) * 100);

    state.penalty = Math.max(0, Math.round(state.penalty * 0.5));

    calculateScore(state);

    const oldStatus = state.status;
    if (state.lossRate >= 60) {
      state.status = 'Offline';
    } else if (state.lossRate >= 20 || state.avgLatency > 250 || state.penalty > 200) {
      state.status = 'Warning';
      if (oldStatus === 'Offline') {
        state.recoveryTime = Date.now();
        state.consecutiveErrors = 0;
      }
    } else {
      state.status = 'Healthy';
      if (oldStatus === 'Offline') {
        state.recoveryTime = Date.now();
        state.consecutiveErrors = 0;
      }
    }
  }));

  updateCandidates();
}

updateCandidates();

setTimeout(() => {
  performHealthChecks().then(() => {
    updateCandidates();
  });
}, 3000);
setInterval(performHealthChecks, 25000);
setInterval(updateCandidates, 5000); // Update rankings every 5s to keep CPU low

const NEXTDNS_DOH_URL = 'https://dns.nextdns.io/53ae9a/RenderProxy';

async function queryNextDNS(queryBuffer, clientIp) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 1200);
  
  const headers = {
    'Content-Type': 'application/dns-message',
    'Accept': 'application/dns-message',
    'Cache-Control': 'no-cache'
  };
  
  if (clientIp && isValidPublicIp(clientIp)) {
    headers['X-Forwarded-For'] = clientIp;
  }
  
  try {
    const res = await fetch(NEXTDNS_DOH_URL, {
      method: 'POST',
      headers: headers,
      body: queryBuffer,
      signal: controller.signal
    });
    
    clearTimeout(timeout);
    if (!res.ok) throw new Error('NextDNS HTTP error ' + res.status);
    const arrayBuffer = await res.arrayBuffer();
    return Buffer.from(arrayBuffer);
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

// Perform DNS routing using NextDNS DoH (Primary) + Speculative UDP Parallel Multicast Racing (Backup)
function raceDNS(queryBuffer, clientIp, timeoutMs = 1200) {
  return new Promise((resolve, reject) => {
    let resolved = false;
    let fallbackTimer = null;
    const activeQueriesSet = new Set();
    const sock = getSocketFromPool();
    const originalTxId = queryBuffer.readUInt16BE(0);
    const myTxId = getNextTxId();

    const upstreamQuery = Buffer.from(queryBuffer);
    upstreamQuery.writeUInt16BE(myTxId, 0);

    const startTime = Date.now();

    const cleanUp = () => {
      resolved = true;
      if (fallbackTimer) clearTimeout(fallbackTimer);
      // Decrement active queries for UDP states
      for (const state of activeQueriesSet) {
        state.activeQueries = Math.max(0, state.activeQueries - 1);
      }
      activeQueriesSet.clear();
      pendingQueries.delete(myTxId);
    };

    const handleFailure = (state, penaltyAmount) => {
      state.realErrorsCount = (state.realErrorsCount || 0) + 1;
      state.penalty = Math.min(1000, (state.penalty || 0) + penaltyAmount);
      state.consecutiveErrors = (state.consecutiveErrors || 0) + 1;
      calculateScore(state);
    };

    const handleSuccess = (state) => {
      state.consecutiveErrors = 0;
      state.penalty = Math.max(0, (state.penalty || 0) - 25);
      calculateScore(state);
    };

    const isTest = process.env.PORT == 3001;

    if (!isTest) {
      // 1. Speculative Priority Lane: Query NextDNS DoH first to enforce customized adblock/security profile
      queryNextDNS(queryBuffer, clientIp).then((responseBuffer) => {
        if (resolved) return;
        cleanUp();
        
        // Re-write the original transaction ID to the DoH response buffer before resolving
        responseBuffer.writeUInt16BE(originalTxId, 0);
        resolve({ responseBuffer, from: 'NextDNS DoH' });
      }).catch((err) => {
        // If NextDNS fails (e.g. timeout, network offline), immediately fail-open to UDP Racing Pool
        if (resolved) return;
        triggerFallback();
      });

      // 2. Speculative Backup Trigger: If NextDNS doesn't answer within 150ms, fire UDP racing pool in parallel
      fallbackTimer = setTimeout(() => {
        triggerFallback();
      }, 150);
    } else {
      // In test mode, bypass NextDNS to test the UDP parallel racing and stats distribution directly
      triggerFallback();
    }

    function triggerFallback() {
      if (resolved) return;
      
      let candidates = activeCandidates;
      const allOffline = candidates.length === 0 || candidates.every(c => c.status === 'Offline');
      if (allOffline) {
        candidates = [
          { ip: '1.1.1.1', name: 'Cloudflare Fallback', score: 50, avgLatency: 50, activeQueries: 0, consecutiveErrors: 0, jitter: 0, lossRate: 0, penalty: 0 },
          { ip: '8.8.8.8', name: 'Google Fallback', score: 50, avgLatency: 50, activeQueries: 0, consecutiveErrors: 0, jitter: 0, lossRate: 0, penalty: 0 }
        ];
      }

      // Register resolve handler for UDP racing pool
      pendingQueries.set(myTxId, {
        resolve: ({ buffer, from }) => {
          if (resolved) return;
          cleanUp();
          
          const responseBuffer = Buffer.from(buffer);
          responseBuffer.writeUInt16BE(originalTxId, 0);
          
          const winner = upstreamStates.find(s => s.ip === from) || candidates.find(c => c.ip === from);
          if (winner) {
            winner.routedQueries = (winner.routedQueries || 0) + 1;
            const latency = Date.now() - startTime;
            const alpha = 0.3;
            winner.realAvgLatency = (winner.realQueriesCount || 0) === 0 
              ? latency 
              : Math.round(alpha * latency + (1 - alpha) * (winner.realAvgLatency || latency));
            winner.realQueriesCount = (winner.realQueriesCount || 0) + 1;
            handleSuccess(winner);
          }
          resolve({ responseBuffer, from });
        },
        reject: () => {
          // Ignore individual write errors, wait for others or timeout
        },
        timeout: setTimeout(() => {
          if (resolved) return;
          cleanUp();
          
          // All UDP fallback upstreams timed out
          candidates.forEach(state => handleFailure(state, 250));
          reject(new Error('DNS query timeout'));
        }, timeoutMs - (Date.now() - startTime))
      });

      // Send to all healthy upstreams concurrently
      candidates.forEach(state => {
        state.activeQueries = (state.activeQueries || 0) + 1;
        activeQueriesSet.add(state);

        sock.send(upstreamQuery, 0, upstreamQuery.length, 53, state.ip, (err) => {
          if (err) {
            state.activeQueries = Math.max(0, state.activeQueries - 1);
            activeQueriesSet.delete(state);
            handleFailure(state, 100);
          }
        });
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



// Periodic cleanup of expired cache entries (every 2 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of cache.entries()) {
    if (now >= val.expiresAt) {
      cache.delete(key);
    }
  }
}, 120000);

// Predictive DNS Prefetching Engine (Self-Learning Markov Transitions & Throttled Queue)
const DOMAIN_ASSOCIATIONS = {
  'facebook.com': ['static.xx.fbcdn.net', 'edge-chat.facebook.com', 'connect.facebook.net', 'scontent.fhan14-1.fna.fbcdn.net'],
  'youtube.com': ['googlevideo.com', 'yt3.ggpht.com', 'i.ytimg.com'],
  'google.com': ['fonts.gstatic.com', 'apis.google.com', 'ssl.gstatic.com', 'www.gstatic.com'],
  'shopee.vn': ['cf.shopee.vn', 'seo-api.shopee.vn', 'down-vn.img.susercontent.com'],
  'tiki.vn': ['salt.tikicdn.com'],
  'vnexpress.net': ['s1.vnecdn.net', 's.vnecdn.net']
};

const queryFrequency = new Map();
const lastClientQuery = new Map(); // clientIp -> { domain, time }
const transitionMap = new Map();    // domainA -> Map of domainB -> count

// Throttled Concurrency Prefetch Queue
const prefetchQueue = [];
let activePrefetches = 0;
const MAX_CONCURRENT_PREFETCH = 3;

function prefetchDomainDirect(name, type = 'A') {
  const cacheKey = `${name.toLowerCase()}:${type}:IN`;
  if (cache.has(cacheKey)) {
    const entry = cache.get(cacheKey);
    const ageSec = (Date.now() - entry.cachedAt) / 1000;
    if (ageSec < entry.originalTtl * 0.7) {
      return Promise.resolve(); // Still fresh, skip prefetch
    }
  }

  const txId = getNextTxId();
  const packet = dnsPacket.encode({
    type: 'query',
    id: txId,
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type, name }]
  });

  return raceDNS(packet, 1200).then(({ responseBuffer }) => {
    try {
      const dnsRes = dnsPacket.decode(responseBuffer);
      if (dnsRes.answers && dnsRes.answers.length > 0) {
        const minTtl = getMinTTL(dnsRes);
        const key = getCacheKey(dnsRes);
        if (key) {
          safeCacheSet(key, {
            buffer: responseBuffer,
            cachedAt: Date.now(),
            originalTtl: minTtl,
            expiresAt: Date.now() + minTtl * 1000
          });
        }
      }
    } catch (e) {
      // Ignore background errors
    }
  }).catch(() => {});
}

function processPrefetchQueue() {
  if (activePrefetches >= MAX_CONCURRENT_PREFETCH || prefetchQueue.length === 0) return;
  
  const task = prefetchQueue.shift();
  activePrefetches++;
  
  prefetchDomainDirect(task.name, task.type)
    .finally(() => {
      activePrefetches--;
      processPrefetchQueue();
    });
}

function enqueuePrefetch(name, type = 'A') {
  const cleanName = name.toLowerCase();
  // Prevent duplicates in queue
  if (prefetchQueue.some(q => q.name === cleanName && q.type === type)) return;
  
  prefetchQueue.push({ name: cleanName, type });
  processPrefetchQueue();
}

function predictAndPrefetch(domainName, clientIp) {
  if (!domainName) return;
  const cleanDomain = domainName.toLowerCase();
  
  // 1. Track frequency
  const currentCount = queryFrequency.get(cleanDomain) || 0;
  queryFrequency.set(cleanDomain, currentCount + 1);

  // 2. Real-Time Pattern Learning (Markov-like transition learning)
  if (clientIp) {
    const last = lastClientQuery.get(clientIp);
    const now = Date.now();
    
    if (last && (now - last.time < 3000)) { // User queried another domain within 3 seconds
      const prev = last.domain;
      if (prev !== cleanDomain && !cleanDomain.includes(prev) && !prev.includes(cleanDomain)) {
        let entry = transitionMap.get(prev);
        if (!entry) {
          entry = new Map();
          transitionMap.set(prev, entry);
        }
        entry.set(cleanDomain, (entry.get(cleanDomain) || 0) + 1);
        
        // Eviction to keep transitionMap size in check
        if (transitionMap.size > 5000) {
          const firstKey = transitionMap.keys().next().value;
          transitionMap.delete(firstKey);
        }
      }
    }
    lastClientQuery.set(clientIp, { domain: cleanDomain, time: now });
  }

  // 3. Prefetch learned sequential transitions (top 3 candidates)
  const learned = transitionMap.get(cleanDomain);
  if (learned) {
    const topLearned = [...learned.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3);
    topLearned.forEach(([target]) => {
      setImmediate(() => enqueuePrefetch(target));
    });
  }

  // 4. Prefetch static associations
  for (const [key, subdomains] of Object.entries(DOMAIN_ASSOCIATIONS)) {
    if (cleanDomain.includes(key)) {
      subdomains.forEach(sub => {
        setImmediate(() => enqueuePrefetch(sub));
      });
      break;
    }
  }
}

// Active Hot Cache Prefetcher: Scan top 15 domains and proactively refresh them before TTL expires
setInterval(() => {
  if (queryFrequency.size === 0) return;
  const sorted = [...queryFrequency.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15);
    
  sorted.forEach(([domain]) => {
    enqueuePrefetch(domain);
  });
}, 45000); // Check and refresh hot domains every 45 seconds // Check and refresh hot domains every 45 seconds

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

let activeClientQueries = 0;
const MAX_CONCURRENT_CLIENT_QUERIES = 250;

async function handleDoH(queryBuffer, clientIp) {
  if (activeClientQueries >= MAX_CONCURRENT_CLIENT_QUERIES) {
    stats.errors++;
    try {
      const decodedQuery = dnsPacket.decode(queryBuffer);
      return dnsPacket.encode({
        type: 'response',
        id: decodedQuery.id,
        flags: dnsPacket.AUTHORITATIVE_ANSWER | 2, // SERVFAIL
        questions: decodedQuery.questions
      });
    } catch (e) {
      throw new Error('Server Busy');
    }
  }

  activeClientQueries++;
  try {
    return await handleDoHInternal(queryBuffer, clientIp);
  } finally {
    activeClientQueries--;
  }
}

async function handleDoHInternal(queryBuffer, clientIp) {
  const startTime = Date.now();
  stats.totalQueries++;

  let dnsQueryObj;
  try {
    dnsQueryObj = dnsPacket.decode(queryBuffer);
  } catch (err) {
    stats.errors++;
    throw new Error('Format Error: Failed to parse DNS query');
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

  if (dnsQueryObj.questions && dnsQueryObj.questions.length > 0) {
    predictAndPrefetch(dnsQueryObj.questions[0].name, clientIp);
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
            raceDNS(queryBuffer, null, 1200)
              .then(({ responseBuffer }) => {
                try {
                  const dnsRespObj = dnsPacket.decode(responseBuffer);
                  const ttl = getMinTTL(dnsRespObj);
                  
                  const isNxDomain = dnsRespObj.rcode === 'NXDOMAIN';
                  const cacheTtl = isNxDomain ? 30 : ttl;

                  safeCacheSet(cacheKey, {
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

  // Request Coalescing: Check if there is already an active outgoing query for the same domain
  if (cacheKey && coalescedQueries.has(cacheKey)) {
    const clientTxId = queryBuffer.readUInt16BE(0);
    return new Promise((resolve, reject) => {
      coalescedQueries.get(cacheKey).push({ resolve, reject, clientTxId });
    });
  }

  const waiters = [];
  if (cacheKey) {
    coalescedQueries.set(cacheKey, waiters);
  }

  try {
    const { responseBuffer, from } = await raceDNS(queryBuffer, clientIp, 1200);
    const latency = Date.now() - startTime;
    stats.totalLatency += latency;
    stats.averageLatency = stats.totalLatency / stats.totalQueries;

    // Cache response (success or NXDOMAIN negative caching)
    if (cacheKey) {
      try {
        const dnsRespObj = dnsPacket.decode(responseBuffer);
        const ttl = getMinTTL(dnsRespObj);
        
        const isNxDomain = dnsRespObj.rcode === 'NXDOMAIN';
        const cacheTtl = isNxDomain ? 30 : ttl; // Cache NXDOMAIN for 30 seconds

        safeCacheSet(cacheKey, {
          buffer: responseBuffer,
          cachedAt: Date.now(),
          originalTtl: cacheTtl,
          expiresAt: Date.now() + cacheTtl * 1000
        });
      } catch (e) {
        // Non-fatal cache failure
      }

      // Resolve all waiters in coalesced group
      coalescedQueries.delete(cacheKey);
      waiters.forEach(w => {
        const resp = Buffer.from(responseBuffer);
        resp.writeUInt16BE(w.clientTxId, 0);
        w.resolve(resp);
      });
    }

    return responseBuffer;
  } catch (err) {
    stats.errors++;
    
    // Reject all waiters in coalesced group on failure
    if (cacheKey) {
      coalescedQueries.delete(cacheKey);
      waiters.forEach(w => {
        w.reject(err);
      });
    }

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
// HTTP Server
const server = http.createServer(async (req, res) => {
  // 1. Fast-Path Client Ping Monitor (Priority lane: absolute minimum processing RTT)
  const urlParts = req.url.split('?');
  const pathname = urlParts[0];

  if (pathname === '/api/ping') {
    res.writeHead(200, { 
      'Content-Type': 'text/plain', 
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    res.end('pong');
    return;
  }

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Parse query parameters manually only when needed (extremely fast)
  let searchParams = null;
  const getSearchParam = (name) => {
    if (!searchParams) {
      searchParams = new URLSearchParams(urlParts[1] || '');
    }
    return searchParams.get(name);
  };

  // Endpoint 1: DoH Handler
  if (pathname === '/dns-query') {
    const clientIp = req.headers['x-forwarded-for']
      ? req.headers['x-forwarded-for'].split(',')[0].trim()
      : req.socket.remoteAddress;

    if (req.method === 'GET') {
      const dnsParam = getSearchParam('dns');
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

  // Endpoint 2: JSON API Stats (Includes detailed load balance & SWR data)
  if (pathname === '/api/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ...stats,
      upstreams: upstreamStates,
      poolSize: currentPoolSize,
      cacheSize: cache.size,
      uptime: process.uptime()
    }));
    return;
  }

  // NextDNS Integration Details
  const NEXTDNS_API_KEY = '54501e382010f84fac9b6dee5fb9b4472229f15e';
  const NEXTDNS_PROFILE_ID = '53ae9a';

  // Endpoint 2.1: Fetch NextDNS Profile Information from REST API
  if (pathname === '/api/nextdns-profile') {
    try {
      const resProfile = await fetch('https://api.nextdns.io/profiles', {
        headers: { 'X-Api-Key': NEXTDNS_API_KEY }
      });
      if (!resProfile.ok) {
        res.writeHead(resProfile.status, { 'Content-Type': 'application/json' });
        res.end(await resProfile.text());
        return;
      }
      const data = await resProfile.json();
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(data));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end(err.message);
    }
    return;
  }

  // Endpoint 2.2: Fetch NextDNS Live Query Logs from REST API
  if (pathname === '/api/nextdns-logs') {
    try {
      const resLogs = await fetch(`https://api.nextdns.io/profiles/${NEXTDNS_PROFILE_ID}/logs?limit=25`, {
        headers: { 'X-Api-Key': NEXTDNS_API_KEY }
      });
      if (!resLogs.ok) {
        res.writeHead(resLogs.status, { 'Content-Type': 'application/json' });
        res.end(await resLogs.text());
        return;
      }
      const data = await resLogs.json();
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(data));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end(err.message);
    }
    return;
  }

  // Endpoint 2.5: Vietnam DNS Scanner
  if (pathname === '/api/test-dns') {
    const ipsToTest = [
      { ip: '203.113.131.1', name: 'Viettel Primary' },
      { ip: '203.113.131.2', name: 'Viettel Secondary' },
      { ip: '203.113.181.1', name: 'Viettel Backup' },
      { ip: '203.162.4.191', name: 'VNPT Primary' },
      { ip: '203.162.4.190', name: 'VNPT Secondary' },
      { ip: '203.162.0.181', name: 'VNPT Backup 1' },
      { ip: '203.162.0.11', name: 'VNPT Backup 2' },
      { ip: '210.245.14.4', name: 'FPT Primary' },
      { ip: '210.245.0.14', name: 'FPT Secondary' },
      { ip: '210.245.0.131', name: 'FPT Backup 1' },
      { ip: '210.245.24.20', name: 'FPT Backup 2' },
      { ip: '210.245.24.22', name: 'FPT Backup 3' },
      { ip: '203.162.57.105', name: 'VNNIC Primary' },
      { ip: '203.162.57.107', name: 'VNNIC Secondary' },
      { ip: '203.119.36.1', name: 'VNNIC Backup 1' },
      { ip: '203.119.38.1', name: 'VNNIC Backup 2' },
      { ip: '203.119.36.106', name: 'VNNIC Public 1' },
      { ip: '203.119.38.106', name: 'VNNIC Public 2' },
      { ip: '118.69.224.242', name: 'CMC Primary' },
      { ip: '118.69.224.243', name: 'CMC Secondary' }
    ];

    const results = [];
    await Promise.all(ipsToTest.map(async (dns) => {
      const res = await pingUpstream(dns.ip);
      results.push({
        ip: dns.ip,
        name: dns.name,
        success: res.success,
        latency: res.success ? res.latency : null
      });
    }));

    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(results, null, 2));
    return;
  }

  // Endpoint 4: Premium Web Dashboard UI
  if (pathname === '/') {
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
            <div class="stat-card" style="border: 1px solid rgba(0, 242, 254, 0.25); box-shadow: 0 0 15px rgba(0, 242, 254, 0.08);">
                <div class="stat-title" style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 8px; height: 8px; border-radius: 50%; background: var(--color-healthy); box-shadow: 0 0 8px var(--color-healthy); display: inline-block; animation: pulse 1.5s infinite;"></span>
                    Ping của bạn đến Server
                </div>
                <div class="stat-value" id="client-to-server-ping">--<span class="stat-unit">ms</span></div>
            </div>
            <div class="stat-card" style="border: 1px solid rgba(168, 85, 247, 0.3); box-shadow: 0 0 15px rgba(168, 85, 247, 0.08);">
                <div class="stat-title" style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 8px; height: 8px; border-radius: 50%; background: #a855f7; box-shadow: 0 0 8px #a855f7; display: inline-block;"></span>
                    Hồ sơ NextDNS liên kết
                </div>
                <div class="stat-value" id="nextdns-profile-name" style="font-size: 1.6rem; color: #c084fc;">Đang tải...</div>
            </div>
        </div>

        <div class="main-panel">
            <h2 style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                <span>Bảng hiệu năng thích ứng (Adaptive DNS & Racing Leaderboard)</span>
                <a href="/api/test-dns" target="_blank" style="font-size: 0.8rem; padding: 6px 12px; border: 1px dashed var(--accent-glow); border-radius: 8px; color: var(--accent-glow); text-decoration: none; transition: all 0.2s;" onmouseover="this.style.background='var(--accent-glow)'; this.style.color='#000'" onmouseout="this.style.background='none'; this.style.color='var(--accent-glow)'">🔍 Quét các DNS Việt Nam</a>
            </h2>
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
        </div>

        <div class="main-panel" style="margin-top: 30px; border-left: 4px solid #a855f7;">
            <h2 style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                <span style="display: flex; align-items: center; gap: 8px;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#c084fc" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                    Nhật ký chặn lọc NextDNS thời gian thực (Live Query Logs)
                </span>
                <span style="font-size: 0.8rem; padding: 4px 8px; background: rgba(168, 85, 247, 0.12); border: 1px solid rgba(168, 85, 247, 0.25); border-radius: 6px; color: #c084fc;">Đang đồng bộ trực tiếp từ API...</span>
            </h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Thời gian</th>
                            <th>Tên miền</th>
                            <th>IP Thiết bị</th>
                            <th>Trạng thái</th>
                            <th>Chi tiết bộ lọc</th>
                        </tr>
                    </thead>
                    <tbody id="nextdns-logs-body">
                        <tr>
                            <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">Đang tải danh sách nhật ký từ API NextDNS...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>



        <footer>
            <p>Thuật toán tối ưu SWR Caching & Dynamic Jitter Racing. Phát triển bởi Antigravity Coding Engine v3.</p>
        </footer>
    </div>

    <script>


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
            const startPing = performance.now();
            let clientPing = null;
            try {
                const pingRes = await fetch('/api/ping');
                if (pingRes.ok) {
                    clientPing = Math.round(performance.now() - startPing);
                }
            } catch (e) {}

            try {
                const res = await fetch('/api/stats');
                const data = await res.json();

                document.getElementById('total-queries').innerText = data.totalQueries.toLocaleString();
                const hitRate = data.totalQueries > 0 ? Math.round((data.cacheHits / data.totalQueries) * 100) : 0;
                document.getElementById('cache-hit-rate').innerHTML = hitRate + '<span class="stat-unit">%</span>';
                document.getElementById('swr-hits').innerText = data.swrHits.toLocaleString();
                document.getElementById('avg-latency').innerHTML = Math.round(data.averageLatency) + '<span class="stat-unit">ms</span>';
                document.getElementById('pool-size').innerHTML = data.poolSize + '<span class="stat-unit">servers</span>';
                
                if (clientPing !== null) {
                    document.getElementById('client-to-server-ping').innerHTML = clientPing + '<span class="stat-unit">ms</span>';
                } else {
                    document.getElementById('client-to-server-ping').innerHTML = '--<span class="stat-unit">ms</span>';
                }

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
            } catch (err) {
                console.error('Error loading stats:', err);
            }
        }

        function escapeHtml(str) {
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
        }

        async function fetchNextDNSProfile() {
            try {
                const res = await fetch('/api/nextdns-profile');
                if (res.ok) {
                    const data = await res.json();
                    if (data.data && data.data.length > 0) {
                        const profile = data.data[0];
                        document.getElementById('nextdns-profile-name').innerText = profile.name + ' (' + profile.id + ')';
                    }
                }
            } catch (e) {
                console.error('Error fetching NextDNS profile:', e);
            }
        }

        async function fetchNextDNSLogs() {
            try {
                const res = await fetch('/api/nextdns-logs');
                if (res.ok) {
                    const data = await res.json();
                    const logsBody = document.getElementById('nextdns-logs-body');
                    logsBody.innerHTML = '';

                    const logs = data.data || [];
                    if (logs.length === 0) {
                        logsBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">Không có nhật ký nào được ghi nhận.</td></tr>';
                        return;
                    }

                    logs.forEach(item => {
                        const dateStr = new Date(item.timestamp).toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                        
                        let statusBadge = '';
                        if (item.status === 'blocked') {
                            statusBadge = '<span class="dns-rank-badge rank-offline" style="padding: 2px 6px;">Đã chặn</span>';
                        } else {
                            statusBadge = '<span class="dns-rank-badge rank-primary" style="background: rgba(0, 255, 170, 0.12); color: var(--color-healthy); border: 1px solid rgba(0, 255, 170, 0.25); padding: 2px 6px;">Bình thường</span>';
                        }

                        let reasonsStr = '--';
                        if (item.status === 'blocked' && item.reasons && item.reasons.length > 0) {
                            reasonsStr = item.reasons.map(r => r.name).join(', ');
                        }

                        const row = document.createElement('tr');
                        row.innerHTML = '<td><span style="color: var(--text-muted); font-size: 0.85rem;">' + dateStr + '</span></td>' +
                            '<td><strong style="color: var(--text-color);">' + escapeHtml(item.domain) + '</strong></td>' +
                            '<td style="font-family: monospace; font-size: 0.85rem;">' + escapeHtml(item.clientIp || '--') + '</td>' +
                            '<td>' + statusBadge + '</td>' +
                            '<td style="font-size: 0.85rem; color: #a855f7; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="' + escapeHtml(reasonsStr) + '">' + escapeHtml(reasonsStr) + '</td>';
                        logsBody.appendChild(row);
                    });
                }
            } catch (e) {
                console.error('Error fetching NextDNS logs:', e);
            }
        }

        fetchStats();
        setInterval(fetchStats, 3000);

        fetchNextDNSProfile();
        fetchNextDNSLogs();
        setInterval(fetchNextDNSLogs, 4000);
    </script>
</body>
</html>`;

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  }
});

server.keepAliveTimeout = 65000; // Keep HTTPS connection open for 65 seconds
server.headersTimeout = 66000;

function prewarmCache() {
  const popularDomains = [
    'google.com', 'facebook.com', 'youtube.com', 'shopee.vn', 'tiktok.com',
    'vnexpress.net', 'zalo.me', 'messenger.com', 'tiki.vn', 'instagram.com',
    'gmail.com', 'github.com', 'wikipedia.org', 'netflix.com', 'chatgpt.com',
    'cloudflare.com', 'apple.com', 'microsoft.com', 'coccoc.com',
    'dantri.com.vn', 'vietnamnet.vn', 'tuoitre.vn', 'kenh14.vn'
  ];
  
  console.log(`[Khởi động] Đang nạp trước ${popularDomains.length} tên miền phổ biến vào RAM Cache...`);
  popularDomains.forEach(domain => {
    enqueuePrefetch(domain);
  });

  // Warm up NextDNS DoH connection to keep TLS session hot and resolve fast on first real query
  const dummyPacket = dnsPacket.encode({
    type: 'query',
    id: 1,
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type: 'A', name: 'google.com' }]
  });
  queryNextDNS(dummyPacket).then(() => {
    console.log('[Khởi động] Đã làm ấm kết nối HTTPS tới NextDNS DoH.');
  }).catch(() => {});
}

server.listen(PORT, () => {
  console.log("Antigravity Hyper-Speed DNS Server running on http://localhost:" + PORT);
  console.log("DNS health-check active monitoring started.");
  prewarmCache();
});
