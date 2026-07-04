const { spawn } = require('child_process');
const http = require('http');
const dnsPacket = require('dns-packet');

const TEST_PORT = 3001; // Avoid conflict with any running instance on 3000

// Helper to base64url encode a buffer
function base64urlEncode(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function runTests() {
  console.log('=== KHIỂM THỬ MÁY CHỦ DNS OVER HTTPS ===');
  
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

  // Chờ 1 giây để server khởi động và bind cổng
  await new Promise(resolve => setTimeout(resolve, 1000));

  let passed = true;

  try {
    const url = `http://localhost:${TEST_PORT}`;
    
    // --- CA KIỂM THỬ 1: Kiểm tra API Stats ---
    console.log('\n[TEST 1]: Kiểm tra API Stats...');
    const statsRes = await fetch(`${url}/api/stats`);
    if (!statsRes.ok) throw new Error(`Stats endpoint failed with status ${statsRes.status}`);
    const stats = await statsRes.json();
    console.log('=> Thống kê ban đầu:', JSON.stringify(stats));
    if (stats.totalQueries !== 0) throw new Error('Ban đầu totalQueries phải bằng 0');
    console.log('=> TEST 1: PASS');

    // --- CA KIỂM THỬ 2: Truy vấn DNS bằng POST (google.com) ---
    console.log('\n[TEST 2]: Truy vấn DNS (google.com) bằng POST...');
    const queryBuffer = dnsPacket.encode({
      type: 'query',
      id: 1234,
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
    const responseArrayBuffer = await postRes.arrayBuffer();
    const responseBuffer = Buffer.from(responseArrayBuffer);
    const postLatency = Date.now() - startPost;
    
    const dnsResponse = dnsPacket.decode(responseBuffer);
    console.log(`=> Độ trễ truy vấn đầu tiên (Cache Miss): ${postLatency}ms`);
    console.log(`=> ID phản hồi: ${dnsResponse.id} (Trùng khớp: ${dnsResponse.id === 1234})`);
    console.log(`=> Câu trả lời nhận được:`, dnsResponse.answers.map(a => `${a.name} -> ${a.address} (TTL: ${a.ttl})`));
    
    if (dnsResponse.answers.length === 0) throw new Error('Không nhận được câu trả lời từ upstream');
    console.log('=> TEST 2: PASS');

    // --- CA KIỂM THỬ 3: Truy vấn lại bằng POST (Kiểm tra Cache Hit) ---
    console.log('\n[TEST 3]: Truy vấn lại google.com bằng POST (Kiểm tra Caching)...');
    // Đổi ID truy vấn mới để xác thực server cập nhật ID trong cache
    const queryBuffer2 = dnsPacket.encode({
      type: 'query',
      id: 5678,
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

    if (!cacheRes.ok) throw new Error(`Cache hit query failed`);
    const cacheResponseBuffer = Buffer.from(await cacheRes.arrayBuffer());
    const cacheLatency = Date.now() - startCache;
    
    const dnsCacheResponse = dnsPacket.decode(cacheResponseBuffer);
    console.log(`=> Độ trễ truy vấn thứ hai (Cache Hit): ${cacheLatency}ms`);
    console.log(`=> ID phản hồi: ${dnsCacheResponse.id} (Trùng khớp: ${dnsCacheResponse.id === 5678})`);
    
    if (cacheLatency > 15) {
      console.warn(`[Cảnh báo]: Tốc độ cache ${cacheLatency}ms hơi chậm (bình thường < 5ms).`);
    }
    if (dnsCacheResponse.answers.length === 0) throw new Error('Không nhận được câu trả lời từ cache');
    console.log('=> TEST 3: PASS');

    // --- CA KIỂM THỬ 4: Truy vấn DNS bằng GET (github.com) ---
    console.log('\n[TEST 4]: Truy vấn DNS (github.com) bằng GET (Base64url)...');
    const queryGetBuffer = dnsPacket.encode({
      type: 'query',
      id: 9999,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: 'A',
        name: 'github.com'
      }]
    });

    const base64Param = base64urlEncode(queryGetBuffer);
    const getRes = await fetch(`${url}/dns-query?dns=${base64Param}`);
    
    if (!getRes.ok) throw new Error(`GET dns-query failed: ${getRes.status}`);
    const getResponseBuffer = Buffer.from(await getRes.arrayBuffer());
    const dnsGetResponse = dnsPacket.decode(getResponseBuffer);
    
    console.log(`=> ID phản hồi GET: ${dnsGetResponse.id} (Trùng khớp: ${dnsGetResponse.id === 9999})`);
    console.log(`=> Câu trả lời nhận được:`, dnsGetResponse.answers.map(a => `${a.name} -> ${a.address}`));
    if (dnsGetResponse.answers.length === 0) throw new Error('Không nhận được câu trả lời qua GET');
    console.log('=> TEST 4: PASS');

    // --- CA KIỂM THỬ 5: Xác nhận lại thống kê hoạt động ---
    console.log('\n[TEST 5]: Kiểm tra lại thống kê (Stats)...');
    const statsRes2 = await fetch(`${url}/api/stats`);
    const stats2 = await statsRes2.json();
    console.log('=> Thống kê sau kiểm thử:', JSON.stringify(stats2));
    if (stats2.totalQueries !== 3) throw new Error('Tổng truy vấn phải là 3 (1 POST miss, 1 POST hit, 1 GET miss)');
    if (stats2.cacheHits !== 1) throw new Error('Số lượt cache hits phải là 1');
    if (stats2.cacheMisses !== 2) throw new Error('Số lượt cache misses phải là 2');
    console.log('=> TEST 5: PASS');

  } catch (err) {
    console.error('\n❌ PHÁT HIỆN LỖI KIỂM THỬ:', err.message);
    passed = false;
  } finally {
    // 4. Dọn dẹp và đóng server
    console.log('\nĐóng máy chủ kiểm thử...');
    serverProc.kill();
    // Chờ tiến trình đóng hẳn
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
