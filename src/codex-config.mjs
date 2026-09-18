function stripComment(line) {
  let quote = null;
  let escaped = false;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote && char === '\\') {
      escaped = true;
      continue;
    }
    if (char === '"' || char === "'") {
      if (quote === char) quote = null;
      else if (!quote) quote = char;
      continue;
    }
    if (char === '#' && !quote) return line.slice(0, i);
  }
  return line;
}

function splitTopLevel(value) {
  const out = [];
  let current = '';
  let quote = null;
  let escaped = false;
  let depth = 0;

  for (const char of value) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (quote && char === '\\') {
      current += char;
      escaped = true;
      continue;
    }
    if (char === '"' || char === "'") {
      if (quote === char) quote = null;
      else if (!quote) quote = char;
      current += char;
      continue;
    }
    if (!quote && (char === '[' || char === '{')) depth += 1;
    if (!quote && (char === ']' || char === '}')) depth -= 1;
    if (char === ',' && !quote && depth === 0) {
      out.push(current.trim());
      current = '';
      continue;
    }
    current += char;
  }

  if (current.trim()) out.push(current.trim());
  return out;
}

function unquote(value) {
  const raw = value.trim();
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    return raw.slice(1, -1);
  }
  return raw;
}

function parseValue(raw) {
  const value = raw.trim();
  if (!value) return '';
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return unquote(value);
  }
  if (value.startsWith('[') && value.endsWith(']')) {
    return splitTopLevel(value.slice(1, -1)).map(parseValue);
  }
  if (value.startsWith('{') && value.endsWith('}')) {
    const object = {};
    for (const part of splitTopLevel(value.slice(1, -1))) {
      const index = part.indexOf('=');
      if (index < 1) throw new Error(`Unsupported TOML inline table entry: ${part}`);
      object[unquote(part.slice(0, index).trim())] = parseValue(part.slice(index + 1));
    }
    return object;
  }
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (/^-?\d+(?:\.\d+)?$/.test(value)) return Number(value);
  return value;
}

function valueComplete(value) {
  let square = 0;
  let curly = 0;
  let quote = null;
  let escaped = false;

  for (const char of value) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote && char === '\\') {
      escaped = true;
      continue;
    }
    if (char === '"' || char === "'") {
      if (quote === char) quote = null;
      else if (!quote) quote = char;
      continue;
    }
    if (quote) continue;
    if (char === '[') square += 1;
    if (char === ']') square -= 1;
    if (char === '{') curly += 1;
    if (char === '}') curly -= 1;
  }

  return !quote && square === 0 && curly === 0;
}

export function codexServerNameFromHeader(header) {
  const match = String(header || '').trim().match(
    /^mcp_servers\.(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9_-]+))(?:\.(.*))?$/
  );
  if (!match) return null;
  return {
    name: match[1] || match[2] || match[3],
    nested: match[4] || ''
  };
}

function envNames(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => {
    if (typeof item === 'string') return item;
    if (item && typeof item === 'object' && typeof item.name === 'string') return item.name;
    return null;
  }).filter(Boolean);
}

function applyAssignment(server, nested, key, value) {
  const signals = server._trustdexSignals;

  if (nested === 'env') {
    server.env[key] = '<redacted>';
    return;
  }
  if (nested === 'http_headers') {
    server._trustdexFingerprintData.httpHeaderKeys.push(key);
    signals.add('static-http-headers');
    return;
  }
  if (nested === 'env_http_headers') {
    server._trustdexFingerprintData.envHttpHeaderKeys.push(key);
    signals.add('env-http-headers');
    return;
  }

  if (nested) return;

  if (key === 'command' && typeof value === 'string') server.command = value;
  else if (key === 'args' && Array.isArray(value)) server.args = value.map(String);
  else if (key === 'url' && typeof value === 'string') server.url = value;
  else if (key === 'cwd' && typeof value === 'string') {
    server.args ??= [];
    server._trustdexFingerprintData.cwd = value;
  } else if (key === 'env' && value && typeof value === 'object' && !Array.isArray(value)) {
    for (const envKey of Object.keys(value)) server.env[envKey] = '<redacted>';
  } else if (key === 'env_vars') {
    for (const envKey of envNames(value)) server.env[envKey] = '<forwarded>';
    if (envNames(value).length) signals.add('env-forwarding');
  } else if (key === 'bearer_token_env_var' && typeof value === 'string') {
    server.env[value] = '<bearer-token>';
    signals.add('secret-env');
  } else if (key === 'http_headers' && value && typeof value === 'object') {
    server._trustdexFingerprintData.httpHeaderKeys.push(...Object.keys(value));
    if (Object.keys(value).length) signals.add('static-http-headers');
  } else if (key === 'env_http_headers' && value && typeof value === 'object') {
    server._trustdexFingerprintData.envHttpHeaderKeys.push(...Object.keys(value));
    if (Object.keys(value).length) signals.add('env-http-headers');
  } else if (key === 'http_headers_helper' && typeof value === 'string') {
    server._trustdexFingerprintData.httpHeadersHelper = value;
    signals.add('header-helper-command');
  } else if (key === 'enabled_tools' && Array.isArray(value)) {
    server._trustdexFingerprintData.enabledTools = value.map(String).sort();
    if (value.some((item) => String(item) === '*')) signals.add('wildcard-tool-scope');
  } else if (key === 'disabled_tools' && Array.isArray(value)) {
    server._trustdexFingerprintData.disabledTools = value.map(String).sort();
  } else if (key === 'default_tools_approval_mode' && value === 'approve') {
    signals.add('auto-approve-tools');
    server._trustdexFingerprintData.defaultToolsApprovalMode = value;
  }
}

export function parseCodexMcpToml(text) {
  const lines = String(text || '').split(/\r?\n/);
  const servers = {};
  let section = null;

  for (let i = 0; i < lines.length; i += 1) {
    const cleaned = stripComment(lines[i]).trim();
    if (!cleaned) continue;

    const headerMatch = cleaned.match(/^\[([^\]]+)\]$/);
    if (headerMatch) {
      section = codexServerNameFromHeader(headerMatch[1]);
      if (section && !servers[section.name]) {
        servers[section.name] = {
          env: {},
          _trustdexSignals: new Set(),
          _trustdexFingerprintData: {
            format: 'codex-toml',
            cwd: null,
            httpHeaderKeys: [],
            envHttpHeaderKeys: [],
            httpHeadersHelper: null,
            enabledTools: [],
            disabledTools: [],
            defaultToolsApprovalMode: null
          }
        };
      }
      continue;
    }

    if (!section) continue;
    const eq = cleaned.indexOf('=');
    if (eq < 1) throw new Error(`Unsupported Codex TOML line ${i + 1}: expected key = value`);

    const key = unquote(cleaned.slice(0, eq).trim());
    let raw = cleaned.slice(eq + 1).trim();
    while (!valueComplete(raw)) {
      i += 1;
      if (i >= lines.length) throw new Error(`Unterminated TOML value for ${key}`);
      raw += `\n${stripComment(lines[i]).trim()}`;
    }

    applyAssignment(servers[section.name], section.nested, key, parseValue(raw));
  }

  for (const server of Object.values(servers)) {
    server._trustdexSignals = [...server._trustdexSignals].sort();
    server._trustdexFingerprintData.httpHeaderKeys =
      [...new Set(server._trustdexFingerprintData.httpHeaderKeys)].sort();
    server._trustdexFingerprintData.envHttpHeaderKeys =
      [...new Set(server._trustdexFingerprintData.envHttpHeaderKeys)].sort();
  }

  return { mcpServers: servers };
}

export function gateCodexToml(text, results, options = {}) {
  const includeAsk = Boolean(options.includeAsk);
  const decisions = new Map(results.map((result) => [result.name, result.action]));
  const lines = String(text || '').split(/\r?\n/);
  const kept = [];
  let keepSection = true;

  for (const line of lines) {
    const cleaned = stripComment(line).trim();
    const headerMatch = cleaned.match(/^\[([^\]]+)\]$/);
    if (headerMatch) {
      const section = codexServerNameFromHeader(headerMatch[1]);
      if (section) {
        const action = decisions.get(section.name);
        keepSection = action === 'allow' || (includeAsk && action === 'ask');
      } else {
        keepSection = true;
      }
    }
    if (keepSection) kept.push(line);
  }

  const output = kept.join('\n');
  return text.endsWith('\n') && !output.endsWith('\n') ? `${output}\n` : output;
}
