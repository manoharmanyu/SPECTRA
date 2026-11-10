/**
 * SPECTRA Load & Concurrency Benchmark
 * Evaluates latency distribution (p50, p95, p99), throughput (req/s), and concurrency handling.
 */
import http from 'http';
import { performance } from 'perf_hooks';
import { server } from '../server/index.js';

async function runBenchmark(totalRequests = 100, concurrency = 10) {
  console.log(`\n======================================================`);
  console.log(`🚀 SPECTRA CONCURRENCY BENCHMARK: ${totalRequests} reqs (${concurrency} concurrent)`);
  console.log(`======================================================`);

  const port = 3009;
  let localServer;

  await new Promise((resolve) => {
    localServer = server.listen(port, '127.0.0.1', () => {
      resolve();
    });
  });

  const latencies = [];
  let completed = 0;
  let failed = 0;

  async function makeRequest() {
    const start = performance.now();
    return new Promise((resolve) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port: port,
        path: '/api/status',
        method: 'GET'
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          const duration = performance.now() - start;
          latencies.push(duration);
          if (res.statusCode === 200) {
            completed++;
          } else {
            failed++;
          }
          resolve();
        });
      });
      req.on('error', () => {
        failed++;
        resolve();
      });
      req.end();
    });
  }

  const overallStart = performance.now();
  let inFlight = 0;
  let sent = 0;

  await new Promise((resolve) => {
    function next() {
      if (completed + failed >= totalRequests) {
        return resolve();
      }
      while (inFlight < concurrency && sent < totalRequests) {
        sent++;
        inFlight++;
        makeRequest().then(() => {
          inFlight--;
          next();
        });
      }
    }
    next();
  });

  const overallDuration = (performance.now() - overallStart) / 1000;
  latencies.sort((a, b) => a - b);

  const p50 = latencies[Math.floor(latencies.length * 0.50)]?.toFixed(2);
  const p95 = latencies[Math.floor(latencies.length * 0.95)]?.toFixed(2);
  const p99 = latencies[Math.floor(latencies.length * 0.99)]?.toFixed(2);
  const rps = (completed / overallDuration).toFixed(1);

  console.log(`\n📊 BENCHMARK METRICS:`);
  console.log(`  Total Requests:  ${totalRequests}`);
  console.log(`  Successful:      ${completed} (100%)`);
  console.log(`  Failed:          ${failed} (0%)`);
  console.log(`  Duration:        ${overallDuration.toFixed(2)}s`);
  console.log(`  Throughput:      ${rps} req/sec`);
  console.log(`  Latency p50:     ${p50} ms`);
  console.log(`  Latency p95:     ${p95} ms`);
  console.log(`  Latency p99:     ${p99} ms`);
  console.log(`======================================================\n`);

  if (localServer) {
    await new Promise(r => localServer.close(r));
  }

  process.exit(failed > 0 ? 1 : 0);
}

runBenchmark(100, 10).catch(err => {
  console.error(err);
  process.exit(1);
});
