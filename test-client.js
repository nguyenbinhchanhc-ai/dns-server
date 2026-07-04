const { spawn } = require('child_process');
const http = require('http');
const dnsPacket = require('dns-packet');

const TEST_PORT = 3001;

async function runTests() {
  console.log('=== KHIỂM THỬ MÁY CHỦ DNS DYNAMIC WEIGHTED LOAD BALANCER ===');
  
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

  // Chờ 1.5 giây để server khởi động và quét health check
  await new Promise(resolve => setTimeout(resolve, 1500));

  let passed = true;

  try {
    const url = `http://localhost:${TEST_PORT}`;
    
    // --- CA KIỂM THỬ 1: Kiểm tra cấu hình upstreams ban đầu ---
    console.log('\n[TEST 1]: Kiểm tra cấu hình upstreams ban đầu...');
    const statsRes = await fetch(`${url}/api/stats`);
    if (!statsRes.ok) throw new Error(`Stats endpoint failed`);
    const stats = await statsRes.json();
    console.log(`=> Tổng số upstreams đang giám sát: ${stats.upstreams.length}`);
    console.log('=> TEST 1: PASS');

    // --- CA KIỂM THỬ 2: Gửi 15 truy vấn khác nhau để kiểm tra chia tải (Load Sharing) ---
    console.log('\n[TEST 2]: Gửi 15 truy vấn A-record khác nhau...');
    
    for (let i = 1; i <= 15; i++) {
      const queryBuffer = dnsPacket.encode({
        type: 'query',
        id: 6000 + i,
        flags: dnsPacket.RECURSION_DESIRED,
        questions: [{
          type: 'A',
          name: `latency-test-${i}.com`
        }]
      });

      const res = await fetch(`${url}/dns-query`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/dns-message',
          'X-Forwarded-For': '27.72.12.34' // Simulate client from Vietnam (Viettel IP)
        },
        body: queryBuffer
      });

      if (!res.ok) throw new Error(`Query thứ ${i} thất bại: ${res.status}`);
      await res.arrayBuffer();
    }
    
    console.log('=> Đã gửi xong 15 truy vấn.');
    console.log('=> TEST 2: PASS');

    // --- CA KIỂM THỬ 3: Xác minh sự phân bổ và đo đạc trễ thực tế ---
    console.log('\n[TEST 3]: Kiểm tra thống kê phân chia tải nhạy trễ...');
    const statsRes2 = await fetch(`${url}/api/stats`);
    const stats2 = await statsRes2.json();
    
    let activeUpstreamsCount = 0;
    console.log('=> Thống kê phân phối tải thực tế:');
    stats2.upstreams.forEach(dns => {
      if (dns.routedQueries > 0) {
        activeUpstreamsCount++;
        console.log(`   * ${dns.name} (${dns.ip}): xử lý ${dns.routedQueries} truy vấn | Trễ thực tế EMA: ${dns.realAvgLatency}ms`);
      }
    });

    console.log(`=> Số máy chủ DNS tham gia xử lý tải: ${activeUpstreamsCount}`);
    
    if (activeUpstreamsCount <= 3) {
      throw new Error(`LỖI: Chỉ có ${activeUpstreamsCount} server xử lý truy vấn! Mở rộng chia tải hoạt động chưa chính xác.`);
    }
    
    console.log('=> TEST 3: PASS');

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
