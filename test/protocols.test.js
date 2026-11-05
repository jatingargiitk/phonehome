import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { parseDns, formatIPv6, parseTlsSni, parseHttpHost, parseVarlink } from '../src/protocols.js';
import { dnsQuery, dnsResponseCname } from './helpers.js';

test('parseDns decodes a query', () => {
  const m = parseDns(dnsQuery('models.example.org', 28));
  assert.equal(m.response, false);
  assert.deepEqual(m.questions, [{ name: 'models.example.org', type: 'AAAA' }]);
});

test('parseDns decodes CNAME + A answers with name compression', () => {
  const m = parseDns(dnsResponseCname('api.example.com', 'edge.example.net', '192.0.2.7'));
  assert.equal(m.response, true);
  assert.deepEqual(
    m.answers.map((a) => [a.name, a.type, a.data]),
    [
      ['api.example.com', 'CNAME', 'edge.example.net'],
      ['edge.example.net', 'A', '192.0.2.7'],
    ],
  );
});

test('parseDns handles the TCP length prefix and rejects junk', () => {
  const q = dnsQuery('example.com');
  const framed = Buffer.concat([Buffer.from([0, q.length]), q]);
  assert.equal(parseDns(framed, { tcp: true }).questions[0].name, 'example.com');
  assert.equal(parseDns(Buffer.from('GET / HTTP/1.1\r\nHost: x\r\n\r\n')), null);
  assert.equal(parseDns(Buffer.alloc(5)), null);
});

test('formatIPv6 compresses zeros', () => {
  assert.equal(formatIPv6(Buffer.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])), '2001:db8::1');
});

test('parseHttpHost reads the Host header', () => {
  assert.equal(parseHttpHost(Buffer.from('GET /v1 HTTP/1.1\r\nHost: telemetry.example.com:8080\r\nUser-Agent: t\r\n\r\n')), 'telemetry.example.com');
  assert.equal(parseHttpHost(Buffer.from('hello')), null);
});

test('parseTlsSni reads the server name from a real Node ClientHello', async () => {
  const hello = await new Promise((resolve, reject) => {
    const server = net.createServer((sock) => {
      sock.once('data', (d) => {
        resolve(d);
        sock.destroy();
        server.close();
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const c = tls.connect({ host: '127.0.0.1', port: server.address().port, servername: 'sni-check.example.net', rejectUnauthorized: false });
      c.on('error', () => {});
    });
    server.on('error', reject);
  });
  assert.equal(parseTlsSni(hello), 'sni-check.example.net');
  assert.equal(parseTlsSni(hello.subarray(0, 20)), null);
});

test('parseVarlink reads systemd-resolved queries and replies', () => {
  const q = parseVarlink(Buffer.from('{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"example.com","flags":0}}\0'));
  assert.deepEqual(q.names, ['example.com']);
  const r = parseVarlink(Buffer.from('{"parameters":{"addresses":[{"ifindex":2,"family":2,"address":[192,0,2,9]}],"name":"example.com","flags":1}}\0'));
  assert.deepEqual(r.addresses, ['192.0.2.9']);
  assert.equal(r.replyName, 'example.com');
});
