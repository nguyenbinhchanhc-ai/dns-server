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
  console.log('=== KHIỂM THỬ MÁY CHỦ DNS ADAPTIVE LOAD BALANCER ===');
  
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
    
    // --- CA KIỂM THỬ 1: Kiểm tra cấu trúc stats của Adaptive DNS ---
    console.log('\n[TEST 1]: Kiểm tra API Stats & Thuộc tính Thích ứng (Adaptive)...');
    const statsRes = await fetch(`${url}/api/stats`);
    if (!statsRes.ok) throw new Error(`Stats endpoint failed: ${statsRes.status}`);
    const stats = await statsRes.json();
    
    const sampleUpstream = stats.upstreams[0];
    console.log(`=> DNS Server mẫu: ${sampleUpstream.name}`);
    console.log(`   - Ping Active: ${sampleUpstream.avgLatency}ms`);
    console.log(`   - Trễ Thực tế EMA ban đầu: ${sampleUpstream.realAvgLatency}ms`);
    console.log(`   - Điểm phạt (Penalty): ${sampleUpstream.penalty}ms`);
    console.log(`   - Số truy vấn thực tế: ${sampleUpstream.realQueriesCount}`);
    
    if (sampleUpstream.realAvgLatency !== 0) throw new Error('Ban đầu realAvgLatency phải bằng 0');
    if (sampleUpstream.penalty !== 0) throw new Error('Ban đầu penalty phải bằng 0');
    console.log('=> TEST 1: PASS');

    // --- CA KIỂM THỬ 2: Gửi truy vấn thực tế lần 1 (google.com) ---
    console.log('\n[TEST 2]: Truy vấn DNS (google.com) bằng POST để kích hoạt đo đạc thực tế...');
    const queryBuffer = dnsPacket.encode({
      type: 'query',
      id: 1010,
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
    console.log(`=> Truy vấn google.com thành công: RTT = ${postLatency}ms`);
    console.log('=> TEST 2: PASS');

    // --- CA KIỂM THỬ 3: Truy vấn lần 2 (github.com) ---
    console.log('\n[TEST 3]: Truy vấn DNS (github.com) bằng GET...');
    const queryGetBuffer = dnsPacket.encode({
      type: 'query',
      id: 2020,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: 'A',
        name: 'github.com'
      }]
    });

    const base64Param = base64urlEncode(queryGetBuffer);
    const getRes = await fetch(`${url}/dns-query?dns=${base64Param}`);
    if (!getRes.ok) throw new Error(`GET dns-query failed`);
    console.log('=> TEST 3: PASS');

    // --- CA KIỂM THỬ 4: Kiểm tra tính toán EMA và Phân phối tải thích ứng ---
    console.log('\n[TEST 4]: Kiểm tra tính toán EMA & Cập nhật thứ hạng định tuyến...');
    const statsRes2 = await fetch(`${url}/api/stats`);
    const stats2 = await statsRes2.json();
    
    console.log('=> Trạng thái thích ứng thực tế của các upstreams đã xử lý truy vấn:');
    let hasRealLatency = false;
    stats2.upstreams.forEach(dns => {
      if (dns.realQueriesCount > 0) {
        console.log(`   * ${dns.name} (${dns.ip}):`);
        console.log(`     - Số truy vấn thực tế: ${dns.realQueriesCount}`);
        console.log(`     - Trễ thực tế trung bình (EMA): ${dns.realAvgLatency}ms`);
        console.log(`     - Điểm phạt hiện tại: ${dns.penalty}ms`);
        console.log(`     - Điểm số định tuyến tổng hợp (Score): ${dns.score}`);
        if (dns.realAvgLatency > 0) {
          hasRealLatency = true;
        }
      }
    });

    if (!hasRealLatency) throw new Error('Hệ thống không cập nhật realAvgLatency (EMA) từ truy vấn thực tế!');
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
