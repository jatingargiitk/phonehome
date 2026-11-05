// Harmless egress demo: one DNS lookup and one HTTPS GET to example.com
// (a domain reserved for documentation, RFC 2606). Nothing is sent but a
// plain GET request; the response body is discarded.
import dns from 'node:dns/promises';
import https from 'node:https';

const { address } = await dns.lookup('example.com');
console.log(`resolved example.com -> ${address}`);

https
  .get('https://example.com/', (res) => {
    res.resume();
    res.on('end', () => console.log(`GET https://example.com/ -> ${res.statusCode}`));
  })
  .on('error', (e) => {
    console.log(`request failed (${e.code}); the attempt is still visible to phonehome`);
  });
