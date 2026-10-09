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

    // --- CA KIỂM THỬ 4: Xác minh Cơ chế Nhận diện Ngữ Cảnh & Điều Phối Thông Minh Từng Truy Vấn ---
    console.log('\n[TEST 4]: Kiểm tra cơ chế nhận diện từng truy vấn một (Smart Query Classifier)...');
    const cases = [
      { domain: 'google.com', type: 'A', expected: 'Google Cloud & Media' },
      { domain: 'github.com', type: 'A', expected: 'Edge CDN & Web' },
      { domain: 'microsoft.com', type: 'A', expected: 'Hạ tầng Doanh nghiệp & Mail' },
      { domain: 'apple.com', type: 'HTTPS', expected: 'HTTP/3 SVCB & ECH' },
      { domain: 'crypto-miner-tracker.com', type: 'A', expected: 'An ninh & Lọc Mã Độc' },
      { domain: 'shopee.vn', type: 'A', expected: 'Anycast Khu Vực (VN)' },
      { domain: 'packages.dev', type: 'A', expected: 'Developer & DNSSEC Anycast' }
    ];

    for (const tc of cases) {
      const dohTestRes = await fetch(`${url}/api/test-doh?name=${encodeURIComponent(tc.domain)}&type=${tc.type}`);
      if (!dohTestRes.ok) throw new Error(`Test-doh request failed for ${tc.domain}`);
      const dohData = await dohTestRes.json();
      if (!dohData.intent || !dohData.intent.category) {
        throw new Error(`Truy vấn ${tc.domain} không được nhận diện ngữ cảnh!`);
      }
      if (dohData.intent.category !== tc.expected) {
        throw new Error(`Phân loại sai cho ${tc.domain}: nhận diện '${dohData.intent.category}', kỳ vọng '${tc.expected}'`);
      }
      console.log(`   * [Đã nhận diện] ${tc.domain} (${tc.type}) => Danh mục: '${dohData.intent.category}' | Lý do: ${dohData.intent.reason} (Trễ: ${dohData.latencyMs}ms)`);
    }

    // Kiểm tra Recent Queries trong /api/stats có lưu intent đầy đủ
    const finalStatsRes = await fetch(`${url}/api/stats`);
    const finalStats = await finalStatsRes.json();
    if (!finalStats.recentQueries || finalStats.recentQueries.length === 0) {
      throw new Error('Dòng recentQueries bị rỗng!');
    }
    const topQuery = finalStats.recentQueries[0];
    if (!topQuery.intent || !topQuery.intent.category) {
      throw new Error('Recent query không lưu intent metadata!');
    }
    console.log(`=> Nhật ký gần nhất: ${topQuery.domain} -> [${topQuery.intent.category}] bởi ${topQuery.upstreamName} (${topQuery.latency}ms)`);
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
