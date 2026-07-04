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
  console.log('=== KHIỂM THỬ MÁY CHỦ DNS HYPER-SPEED & SWR CACHING ===');
  
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

  // Chờ 1.5 giây để server khởi động và chạy health check ban đầu
  await new Promise(resolve => setTimeout(resolve, 1500));

  let passed = true;

  try {
    const url = `http://localhost:${TEST_PORT}`;
    
    // --- CA KIỂM THỬ 1: Kiểm tra các chỉ số Hyper-Speed stats ---
    console.log('\n[TEST 1]: Kiểm tra các trường chỉ số Hyper-Speed & SWR...');
    const statsRes = await fetch(`${url}/api/stats`);
    if (!statsRes.ok) throw new Error(`Stats endpoint failed: ${statsRes.status}`);
    const stats = await statsRes.json();
    
    console.log(`=> Kích thước Racing Pool động hiện tại: ${stats.poolSize} servers`);
    console.log(`=> Số lượt SWR Hits ban đầu: ${stats.swrHits}`);
    
    if (typeof stats.swrHits !== 'number') throw new Error('Trường swrHits phải là kiểu số');
    if (stats.poolSize < 2 || stats.poolSize > 4) throw new Error('Kích thước Racing Pool phải nằm trong khoảng từ 2 đến 4');
    console.log('=> TEST 1: PASS');

    // --- CA KIỂM THỬ 2: Gửi truy vấn thực tế lần 1 (google.com) ---
    console.log('\n[TEST 2]: Truy vấn DNS (google.com) bằng POST (Cache Miss)...');
    const queryBuffer = dnsPacket.encode({
      type: 'query',
      id: 3030,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: 'A',
        name: 'google.com'
      }]
    });

    const startPost = Date.now();
    const postRes = await fetch(`${url}/dns-query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/dns-message' },
      body: queryBuffer
    });

    if (!postRes.ok) throw new Error(`POST dns-query failed`);
    const responseBuffer = Buffer.from(await postRes.arrayBuffer());
    const postLatency = Date.now() - startPost;
    
    const dnsResponse = dnsPacket.decode(responseBuffer);
    console.log(`=> Độ trễ (Cache Miss): ${postLatency}ms`);
    console.log('=> TEST 2: PASS');

    // --- CA KIỂM THỬ 3: Truy vấn lần 2 (google.com) - Xác nhận Cache Hit ---
    console.log('\n[TEST 3]: Truy vấn lại google.com (Yêu cầu nhận ngay từ Cache)...');
    const queryBuffer2 = dnsPacket.encode({
      type: 'query',
      id: 4040,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: 'A',
        name: 'google.com'
      }]
    });

    const startCache = Date.now();
    const cacheRes = await fetch(`${url}/dns-query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/dns-message' },
      body: queryBuffer2
    });

    if (!cacheRes.ok) throw new Error('Cache lookup failed');
    const cacheResponseBuffer = Buffer.from(await cacheRes.arrayBuffer());
    const cacheLatency = Date.now() - startCache;
    
    const dnsCacheResponse = dnsPacket.decode(cacheResponseBuffer);
    console.log(`=> Độ trễ (Cache Hit): ${cacheLatency}ms (Trùng khớp ID: ${dnsCacheResponse.id === 4040})`);
    
    if (cacheLatency > 15) throw new Error('Độ trễ Cache Hit quá cao, không đạt tiêu chuẩn lướt web nhanh');
    console.log('=> TEST 3: PASS');

    // --- CA KIỂM THỬ 4: Kiểm tra thống kê cuối ---
    console.log('\n[TEST 4]: Kiểm tra lại thống kê tổng hợp...');
    const statsRes2 = await fetch(`${url}/api/stats`);
    const stats2 = await statsRes2.json();
    console.log('=> Thống kê tổng hợp:', JSON.stringify({
      totalQueries: stats2.totalQueries,
      cacheHits: stats2.cacheHits,
      swrHits: stats2.swrHits,
      cacheMisses: stats2.cacheMisses,
      poolSize: stats2.poolSize
    }));
    
    if (stats2.cacheHits !== 1) throw new Error('Số lượt cache hit phải bằng 1');
    console.log('=> TEST 4: PASS');

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
