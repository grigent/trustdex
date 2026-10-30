// A small TOML lexer for the subset TrustDex inspects. It tokenizes the whole document
// correctly (basic, literal, and multi-line strings, arrays, inline tables, dotted and
// quoted keys, comments) so a value can never swallow a following table and a table
// header can never be skipped because of spacing or quoting. Values are decoded only
// when a caller asks for them; anything unsupported throws without echoing input.

const BARE_KEY_RE = /[A-Za-z0-9_-]/;
const ESCAPES = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' };

class Lexer {
  constructor(text) {
    this.text = String(text || '');
    // A leading byte-order mark is allowed and skipped, as TOML parsers do. Offsets stay
    // relative to the original text so gating can cut it exactly.
    this.i = this.text.startsWith('\uFEFF') ? 1 : 0;
    // Control characters other than tab, and a carriage return that does not start a
    // CRLF line ending, are invalid anywhere in TOML; rejecting them up front prevents
    // a hidden line break from moving text out of a comment or string.
    const invalid = this.text.search(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)/);
    if (invalid >= 0) {
      this.i = invalid;
      this.fail('control character');
    }
  }

  get done() { return this.i >= this.text.length; }

  peek(offset = 0) { return this.text[this.i + offset]; }

  startsWith(token) { return this.text.startsWith(token, this.i); }

  line() {
    let line = 1;
    for (let k = 0; k < this.i && k < this.text.length; k += 1) if (this.text[k] === '\n') line += 1;
    return line;
  }

  fail(message) {
    throw new Error(`Unsupported TOML at line ${this.line()}: ${message}.`);
  }

  skipSpaces() {
    while (this.peek() === ' ' || this.peek() === '\t') this.i += 1;
  }

  skipComment() {
    if (this.peek() !== '#') return;
    while (!this.done && this.peek() !== '\n') this.i += 1;
  }

  skipBlank() {
    for (;;) {
      this.skipSpaces();
      this.skipComment();
      if (this.peek() === '\n') { this.i += 1; continue; }
      if (this.peek() === '\r' && this.peek(1) === '\n') { this.i += 2; continue; }
      return;
    }
  }

  endOfLine() {
    this.skipSpaces();
    this.skipComment();
    if (this.done) return;
    if (this.peek() === '\n') { this.i += 1; return; }
    if (this.peek() === '\r' && this.peek(1) === '\n') { this.i += 2; return; }
    this.fail('expected end of line');
  }

  basicString() {
    this.i += 1;
    let out = '';
    while (!this.done) {
      const char = this.peek();
      if (char === '"') { this.i += 1; return out; }
      if (char === '\n' || char === '\r') this.fail('newline in a string');
      if (char === '\\') { out += this.escape(); continue; }
      out += char;
      this.i += 1;
    }
    return this.fail('unterminated string');
  }

  escape() {
    const next = this.peek(1);
    if (Object.hasOwn(ESCAPES, next)) { this.i += 2; return ESCAPES[next]; }
    const width = next === 'u' ? 4 : next === 'U' ? 8 : 0;
    const hex = this.text.slice(this.i + 2, this.i + 2 + width);
    if (!width || !/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== width) this.fail('invalid escape');
    const code = Number.parseInt(hex, 16);
    if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) this.fail('invalid escape');
    this.i += 2 + width;
    return String.fromCodePoint(code);
  }

  literalString() {
    this.i += 1;
    const end = this.text.indexOf("'", this.i);
    const newline = this.text.slice(this.i, end < 0 ? undefined : end).search(/[\r\n]/);
    if (end < 0 || newline >= 0) this.fail('unterminated literal string');
    const value = this.text.slice(this.i, end);
    this.i = end + 1;
    return value;
  }

  multilineBasic() {
    this.i += 3;
    if (this.startsWith('\r\n')) this.i += 2;
    else if (this.peek() === '\n') this.i += 1;
    let out = '';
    while (!this.done) {
      if (this.startsWith('"""')) {
        let quotes = 3;
        while (this.peek(quotes) === '"' && quotes < 5) quotes += 1;
        out += '"'.repeat(quotes - 3);
        this.i += quotes;
        return out;
      }
      const char = this.peek();
      if (char === '\\') {
        const rest = this.text.slice(this.i + 1).match(/^[ \t]*\r?\n/);
        if (rest) {
          this.i += 1;
          while (/[ \t\r\n]/.test(this.peek() || '')) this.i += 1;
          continue;
        }
        out += this.escape();
        continue;
      }
      out += char;
      this.i += 1;
    }
    return this.fail('unterminated multi-line string');
  }

  multilineLiteral() {
    this.i += 3;
    if (this.startsWith('\r\n')) this.i += 2;
    else if (this.peek() === '\n') this.i += 1;
    const end = this.text.indexOf("'''", this.i);
    if (end < 0) this.fail('unterminated multi-line literal string');
    let close = end;
    while (this.text[close + 3] === "'" && close - end < 2) close += 1;
    const value = this.text.slice(this.i, close);
    this.i = close + 3;
    return value;
  }

  key() {
    const path = [];
    for (;;) {
      this.skipSpaces();
      const char = this.peek();
      if (char === '"') {
        if (this.startsWith('"""')) this.fail('multi-line string used as a key');
        path.push(this.basicString());
      } else if (char === "'") {
        if (this.startsWith("'''")) this.fail('multi-line string used as a key');
        path.push(this.literalString());
      } else {
        const start = this.i;
        while (!this.done && BARE_KEY_RE.test(this.peek())) this.i += 1;
        if (this.i === start) this.fail('expected a key');
        path.push(this.text.slice(start, this.i));
      }
      this.skipSpaces();
      if (this.peek() !== '.') return path;
      this.i += 1;
    }
  }

  // Returns { kind, value } where kind is string, array, table, or bare.
  value() {
    const char = this.peek();
    if (this.startsWith('"""')) return { kind: 'string', value: this.multilineBasic() };
    if (this.startsWith("'''")) return { kind: 'string', value: this.multilineLiteral() };
    if (char === '"') return { kind: 'string', value: this.basicString() };
    if (char === "'") return { kind: 'string', value: this.literalString() };
    if (char === '[') {
      this.i += 1;
      const items = [];
      for (;;) {
        this.skipBlank();
        if (this.peek() === ']') { this.i += 1; return { kind: 'array', value: items }; }
        if (this.done) this.fail('unterminated array');
        items.push(this.value());
        this.skipBlank();
        if (this.peek() === ',') { this.i += 1; continue; }
        if (this.peek() === ']') { this.i += 1; return { kind: 'array', value: items }; }
        this.fail('expected "," or "]" in an array');
      }
    }
    if (char === '{') {
      this.i += 1;
      const entries = [];
      this.skipSpaces();
      if (this.peek() === '}') { this.i += 1; return { kind: 'table', value: entries }; }
      for (;;) {
        const path = this.key();
        if (this.peek() !== '=') this.fail('expected "=" in an inline table');
        this.i += 1;
        this.skipSpaces();
        entries.push({ path, value: this.value() });
        this.skipSpaces();
        if (this.peek() === ',') { this.i += 1; continue; }
        if (this.peek() === '}') { this.i += 1; return { kind: 'table', value: entries }; }
        this.fail('expected "," or "}" in an inline table');
      }
    }
    const start = this.i;
    while (!this.done && !/[\s,\]}#]/.test(this.peek())) this.i += 1;
    if (this.i === start) this.fail('expected a value');
    const value = this.text.slice(start, this.i);
    // Numbers, booleans, and dates only contain these characters.
    if (!/^[A-Za-z0-9_:.+-]+$/.test(value)) this.fail('invalid value');
    return { kind: 'bare', value };
  }
}

// Parse a document into statements: tables, array tables, and key/value pairs, each with
// its full key path and source span [start, end) including the trailing newline.
export function parseTomlStatements(text) {
  const lexer = new Lexer(text);
  const statements = [];
  let table = [];
  for (;;) {
    lexer.skipBlank();
    if (lexer.done) break;
    const start = lexer.i;
    if (lexer.peek() === '[') {
      const array = lexer.startsWith('[[');
      lexer.i += array ? 2 : 1;
      const path = lexer.key();
      if (!lexer.startsWith(array ? ']]' : ']')) lexer.fail('expected the end of a table header');
      lexer.i += array ? 2 : 1;
      lexer.endOfLine();
      table = path;
      statements.push({ type: array ? 'array-table' : 'table', path, start, end: lexer.i });
      continue;
    }
    const key = lexer.key();
    if (lexer.peek() !== '=') lexer.fail('expected "="');
    lexer.i += 1;
    lexer.skipSpaces();
    const value = lexer.value();
    lexer.endOfLine();
    statements.push({ type: 'value', table, key, path: [...table, ...key], value, start, end: lexer.i });
  }
  return statements;
}

// Decode a lexed value into plain JavaScript. Bare values other than booleans and
// plain decimal numbers (dates, hex, inf, nan, words) are rejected.
export function decodeTomlValue(node) {
  if (node.kind === 'string') return node.value;
  if (node.kind === 'array') return node.value.map(decodeTomlValue);
  if (node.kind === 'table') {
    const object = Object.create(null);
    for (const entry of node.value) {
      let target = object;
      entry.path.slice(0, -1).forEach((segment) => {
        if (!Object.hasOwn(target, segment)) target[segment] = Object.create(null);
        target = target[segment];
        if (!target || typeof target !== 'object' || Array.isArray(target)) {
          throw new Error('Unsupported TOML inline table: conflicting keys.');
        }
      });
      const last = entry.path[entry.path.length - 1];
      if (Object.hasOwn(target, last)) throw new Error('Unsupported TOML inline table: duplicate key.');
      target[last] = decodeTomlValue(entry.value);
    }
    return object;
  }
  if (node.value === 'true') return true;
  if (node.value === 'false') return false;
  if (/^[+-]?\d+(?:\.\d+)?$/.test(node.value)) return Number(node.value);
  throw new Error('Unsupported TOML value: quote strings and use only strings, numbers, booleans, arrays, and inline tables.');
}
