const { spawn } = require('child_process');
const http = require('http');
const dnsPacket = require('dns-packet');

const TEST_PORT = 3001;

function base64urlEncode(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function runTests() {
  console.log('=== KHIỂM THỬ MÁY CHỦ DNS LOAD BALANCER & ACTIVE MONITOR ===');
  
  // 1. Khởi động server
  const serverProc = spawn('node', ['server.js'], {
    env: { ...process.env, PORT: TEST_PORT }
  });

  serverProc.stdout.on('data', (data) => {
    // console.log(`[Server Out]: ${data.toString().trim()}`);
  });

  serverProc.stderr.on('data', (data) => {
    console.error(`[Server Err]: ${data.toString().trim()}`);
  });

  // Chờ 1.5 giây để server khởi động, chạy lượt active ping đầu tiên và bind cổng
  await new Promise(resolve => setTimeout(resolve, 1500));

  let passed = true;

  try {
    const url = `http://localhost:${TEST_PORT}`;
    
    // --- CA KIỂM THỬ 1: Kiểm tra API Stats ban đầu ---
    console.log('\n[TEST 1]: Kiểm tra API Stats & Active Monitoring...');
    const statsRes = await fetch(`${url}/api/stats`);
    if (!statsRes.ok) throw new Error(`Stats endpoint failed: ${statsRes.status}`);
    const stats = await statsRes.json();
    
    console.log(`=> Danh sách upstreams đã quét: ${stats.upstreams.length} servers`);
    console.log(`=> Ping của Cloudflare Primary (1.1.1.1): ${stats.upstreams[0].avgLatency}ms (Trạng thái: ${stats.upstreams[0].status})`);
    
    if (stats.totalQueries !== 0) throw new Error('Ban đầu totalQueries phải bằng 0');
    if (stats.upstreams.length < 5) throw new Error('Không đủ số lượng DNS servers');
    console.log('=> TEST 1: PASS');

    // --- CA KIỂM THỬ 2: Truy vấn DNS (google.com) bằng POST (Cache Miss & Racing) ---
    console.log('\n[TEST 2]: Truy vấn DNS (google.com) bằng POST...');
    const queryBuffer = dnsPacket.encode({
      type: 'query',
      id: 1111,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: 'A',
        name: 'google.com'
      }]
    });

    const startPost = Date.now();
    const postRes = await fetch(`${url}/dns-query`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message'
      },
      body: queryBuffer
    });

    if (!postRes.ok) throw new Error(`POST dns-query failed: ${postRes.status}`);
    const responseBuffer = Buffer.from(await postRes.arrayBuffer());
    const postLatency = Date.now() - startPost;
    
    const dnsResponse = dnsPacket.decode(responseBuffer);
    console.log(`=> Độ trễ truy vấn đầu tiên (Cache Miss): ${postLatency}ms`);
    console.log(`=> ID phản hồi: ${dnsResponse.id} (Trùng khớp: ${dnsResponse.id === 1111})`);
    if (dnsResponse.answers.length === 0) throw new Error('Không nhận được câu trả lời');
    console.log('=> TEST 2: PASS');

    // --- CA KIỂM THỬ 3: Truy vấn lại (Cache Hit) ---
    console.log('\n[TEST 3]: Truy vấn lại google.com để kiểm tra Cache Hit...');
    const queryBuffer2 = dnsPacket.encode({
      type: 'query',
      id: 2222,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: 'A',
        name: 'google.com'
      }]
    });

    const startCache = Date.now();
    const cacheRes = await fetch(`${url}/dns-query`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message'
      },
      body: queryBuffer2
    });

    if (!cacheRes.ok) throw new Error('Cache lookup failed');
    const cacheResponseBuffer = Buffer.from(await cacheRes.arrayBuffer());
    const cacheLatency = Date.now() - startCache;
    
    const dnsCacheResponse = dnsPacket.decode(cacheResponseBuffer);
    console.log(`=> Độ trễ truy vấn Cache Hit: ${cacheLatency}ms`);
    console.log(`=> ID phản hồi: ${dnsCacheResponse.id} (Trùng khớp: ${dnsCacheResponse.id === 2222})`);
    if (cacheLatency > 15) console.warn('[Cảnh báo]: Cache phản hồi hơi chậm');
    console.log('=> TEST 3: PASS');

    // --- CA KIỂM THỬ 4: Truy vấn bằng GET Base64url (github.com) ---
    console.log('\n[TEST 4]: Truy vấn DNS (github.com) bằng GET (Base64url)...');
    const queryGetBuffer = dnsPacket.encode({
      type: 'query',
      id: 3333,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: 'A',
        name: 'github.com'
      }]
    });

    const base64Param = base64urlEncode(queryGetBuffer);
    const getRes = await fetch(`${url}/dns-query?dns=${base64Param}`);
    
    if (!getRes.ok) throw new Error(`GET dns-query failed`);
    const getResponseBuffer = Buffer.from(await getRes.arrayBuffer());
    const dnsGetResponse = dnsPacket.decode(getResponseBuffer);
    
    console.log(`=> ID phản hồi GET: ${dnsGetResponse.id} (Trùng khớp: ${dnsGetResponse.id === 3333})`);
    console.log('=> TEST 4: PASS');

    // --- CA KIỂM THỬ 5: Xác nhận số lượng chia tải & xếp hạng ---
    console.log('\n[TEST 5]: Kiểm tra số lượng phân phối chia tải & Thống kê...');
    const statsRes2 = await fetch(`${url}/api/stats`);
    const stats2 = await statsRes2.json();
    
    console.log('=> Thống kê phân chia tải thực tế giữa các DNS:');
    let totalRouted = 0;
    stats2.upstreams.forEach(dns => {
      if (dns.routedQueries > 0) {
        console.log(`   * ${dns.name} (${dns.ip}): xử lý ${dns.routedQueries} truy vấn (Ping: ${dns.avgLatency}ms)`);
        totalRouted += dns.routedQueries;
      }
    });

    if (stats2.totalQueries !== 3) throw new Error('Tổng số lượng truy vấn không chính xác');
    if (stats2.cacheHits !== 1) throw new Error('Lượt cache hit không chính xác');
    if (stats2.cacheMisses !== 2) throw new Error('Lượt cache miss không chính xác');
    if (totalRouted !== 2) throw new Error('Số lượng chia tải thực tế cho DNS upstreams không khớp với số cache miss (2)');
    
    console.log('=> TEST 5: PASS');

  } catch (err) {
    console.error('\n❌ PHÁT HIỆN LỖI KIỂM THỬ:', err.message);
    passed = false;
  } finally {
    console.log('\nĐóng máy chủ kiểm thử...');
    serverProc.kill();
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  if (passed) {
    console.log('\n✅ TẤT CẢ CÁC CA KIỂM THỬ ĐÃ THÀNH CÔNG!');
    process.exit(0);
  } else {
    console.error('\n❌ KIỂM THỬ THẤT BẠI!');
    process.exit(1);
  }
}

runTests();
