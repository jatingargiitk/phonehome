// No-network demo: does some work and talks to itself over loopback.
// Loopback traffic is local, so phonehome reports 0 egress.
import http from 'node:http';
import { createHash } from 'node:crypto';

let digest = 'phonehome';
for (let i = 0; i < 100000; i++) digest = createHash('sha256').update(digest).digest('hex');
console.log(`sha256 x100000: ${digest.slice(0, 16)}...`);

const server = http.createServer((req, res) => res.end('ok from 127.0.0.1'));
server.listen(0, '127.0.0.1', () => {
  const { port } = server.address();
  http.get(`http://127.0.0.1:${port}/`, (res) => {
    let body = '';
    res.on('data', (d) => (body += d));
    res.on('end', () => {
      console.log(`loopback GET -> ${body}`);
      server.close();
    });
  });
});
