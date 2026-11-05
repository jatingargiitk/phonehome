// Decode the C-style string literals strace prints (with -x, non-printable
// strings come out as \xNN escapes). Returns a Buffer of the raw bytes.

const SIMPLE = { n: 0x0a, t: 0x09, r: 0x0d, v: 0x0b, f: 0x0c, a: 0x07, b: 0x08, '"': 0x22, '\\': 0x5c, "'": 0x27 };

export function unescapeC(body) {
  const out = [];
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch !== '\\') {
      const code = body.charCodeAt(i);
      if (code < 0x80) out.push(code);
      else for (const b of Buffer.from(ch, 'utf8')) out.push(b);
      continue;
    }
    const next = body[i + 1];
    if (next === 'x') {
      out.push(parseInt(body.slice(i + 2, i + 4), 16));
      i += 3;
    } else if (next >= '0' && next <= '7') {
      let j = i + 1;
      let digits = '';
      while (j < body.length && digits.length < 3 && body[j] >= '0' && body[j] <= '7') digits += body[j++];
      out.push(parseInt(digits, 8));
      i = j - 1;
    } else if (next in SIMPLE) {
      out.push(SIMPLE[next]);
      i += 1;
    } else {
      out.push(body.charCodeAt(i + 1));
      i += 1;
    }
  }
  return Buffer.from(out);
}

// Every "..." literal in an strace argument list, decoded.
export function stringLiterals(args) {
  const re = /"((?:[^"\\]|\\.)*)"/g;
  const found = [];
  let m;
  while ((m = re.exec(args))) found.push(unescapeC(m[1]));
  return found;
}
