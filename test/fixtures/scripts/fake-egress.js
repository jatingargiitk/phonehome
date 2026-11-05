// Test helper: makes egress attempts that go nowhere. 192.0.2.0/24 and
// 2001:db8::/32 are reserved documentation ranges (RFC 5737 / RFC 3849).
import dgram from 'node:dgram';
import net from 'node:net';

function dnsQuery(name) {
  const parts = [Buffer.from([0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])];
  for (const l of name.split('.')) parts.push(Buffer.from([l.length]), Buffer.from(l));
  parts.push(Buffer.from([0, 0, 1, 0, 1]));
  return Buffer.concat(parts);
}

const udp = dgram.createSocket('udp4');
await new Promise((r) => udp.send(dnsQuery('phonehome-test.example'), 53, '192.0.2.53', r));
udp.close();

await new Promise((resolve) => {
  const s = net.connect({ host: '192.0.2.10', port: 8443 });
  s.on('error', resolve);
  setTimeout(() => {
    s.destroy();
    resolve();
  }, 100);
});
process.exit(Number(process.argv[2] || 0));
