import crypto from 'node:crypto';

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function sha256Text(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

export function sha256Json(value) {
  return sha256Text(canonicalJson(value));
}

// Deeper JSON is rejected before recursive inspection can exhaust the stack.
export const MAX_JSON_DEPTH = 128;

// JSON.parse keeps the last of two equal keys, while other readers keep the first or
// reject the file, and turns a "__proto__" key into an ordinary property that object
// spreads treat differently. Inputs with either are rejected instead of guessed.
export function parseStrictJson(text) {
  const value = JSON.parse(text);
  const stack = [];
  let expectKey = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (char === '"') {
      let end = i + 1;
      while (text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top && expectKey) {
        const key = JSON.parse(text.slice(i, end + 1));
        if (key === '__proto__') throw new SyntaxError('Unsupported JSON: a "__proto__" key.');
        if (top.has(key)) throw new SyntaxError('Unsupported JSON: a key is defined more than once.');
        top.add(key);
        expectKey = false;
      }
      i = end;
    } else if (char === '{') {
      stack.push(new Set());
      if (stack.length > MAX_JSON_DEPTH) throw new SyntaxError(`Unsupported JSON: values are nested more than ${MAX_JSON_DEPTH} levels deep.`);
      expectKey = true;
    } else if (char === '[') {
      stack.push(null);
      if (stack.length > MAX_JSON_DEPTH) throw new SyntaxError(`Unsupported JSON: values are nested more than ${MAX_JSON_DEPTH} levels deep.`);
    } else if (char === '}' || char === ']') {
      stack.pop();
      expectKey = false;
    } else if (char === ',') {
      expectKey = stack[stack.length - 1] instanceof Set;
    }
  }
  return value;
}
