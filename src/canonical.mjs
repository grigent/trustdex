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

// The first structural problem in text that JSON.parse accepts: a member name repeated in
// one object ("duplicate"), a "__proto__" member ("proto"), or nesting deeper than
// MAX_JSON_DEPTH ("depth"). JSON.parse keeps the last of two equal names silently, so a
// later "revoked": [] or "hooks": null could erase an earlier value; a "__proto__" member
// becomes an ordinary property that object spreads treat differently.
export function jsonMemberProblem(text) {
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
        if (top.has(key)) return 'duplicate';
        if (key === '__proto__') return 'proto';
        top.add(key);
        expectKey = false;
      }
      i = end;
    } else if (char === '{' || char === '[') {
      stack.push(char === '{' ? new Set() : null);
      if (stack.length > MAX_JSON_DEPTH) return 'depth';
      expectKey = char === '{';
    } else if (char === '}' || char === ']') {
      stack.pop();
      expectKey = false;
    } else if (char === ',') {
      expectKey = stack[stack.length - 1] instanceof Set;
    }
  }
  return null;
}

const JSON_PROBLEMS = {
  duplicate: 'a key is defined more than once.',
  proto: 'a "__proto__" key.',
  depth: `values are nested more than ${MAX_JSON_DEPTH} levels deep.`
};

/** JSON.parse that rejects repeated member names, "__proto__" members, and deep nesting. */
export function parseStrictJson(text) {
  const value = JSON.parse(text);
  const problem = jsonMemberProblem(text);
  if (problem) throw new SyntaxError(`Unsupported JSON: ${JSON_PROBLEMS[problem]}`);
  return value;
}

/**
 * Throws when a JSON text repeats a member name inside one object, has a "__proto__"
 * member, or nests too deeply. Call only on text that JSON.parse accepts.
 */
export function rejectDuplicateJsonMembers(text, where = 'JSON input') {
  const problem = jsonMemberProblem(text);
  if (problem === 'duplicate') throw new Error(`${where} repeats a field name.`);
  if (problem === 'proto') throw new Error(`${where} has a "__proto__" field.`);
  if (problem === 'depth') throw new Error(`${where} is nested more than ${MAX_JSON_DEPTH} levels deep.`);
}
