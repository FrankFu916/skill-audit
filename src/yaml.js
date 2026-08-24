/**
 * Minimal YAML frontmatter parser — zero dependencies.
 *
 * Supports the subset of YAML that SKILL.md files actually use:
 *   - scalar values (strings, numbers, booleans, null)
 *   - single/double-quoted strings (multi-line folded with leading whitespace)
 *   - inline flow sequences and mappings: [a, b] / {a: 1}
 *   - block sequences (- item), including "- key: value" compact mappings
 *   - block mappings nested by indentation
 *
 * It intentionally does NOT try to be a full YAML implementation; anything it
 * cannot understand is surfaced via `warnings` so audits never fail silently.
 */

/** Extract `---` delimited frontmatter from markdown content.
 * @returns {{ raw: string | null, body: string }}
 */
export function splitFrontmatter(content) {
  const normalized = content.replace(/\r\n/g, '\n');
  if (!normalized.startsWith('---')) {
    return { raw: null, body: normalized };
  }
  const firstLineEnd = normalized.indexOf('\n');
  if (firstLineEnd === -1) return { raw: null, body: normalized };
  const opener = normalized.slice(0, firstLineEnd).trim();
  if (opener !== '---') {
    // e.g. "---js" code fence at position 0 is not frontmatter
    return { raw: null, body: normalized };
  }
  const closer = normalized.indexOf('\n---', firstLineEnd);
  if (closer === -1) {
    return { raw: null, body: normalized };
  }
  const afterClosing = normalized.slice(closer + 4); // skip "\n---"
  const nl = afterClosing.indexOf('\n');
  const rest = nl === -1 ? '' : afterClosing.slice(nl + 1);
  return {
    raw: normalized.slice(firstLineEnd + 1, closer),
    body: rest,
  };
}

function unquote(value) {
  const s = value.trim();
  if (s.length >= 2 && s[0] === "'" && s[s.length - 1] === "'") {
    return s.slice(1, -1).replace(/''/g, "'");
  }
  if (s.length >= 2 && s[0] === '"' && s[s.length - 1] === '"') {
    return s
      .slice(1, -1)
      .replace(/\\(["\\])/g, '$1')
      .replace(/\\n/g, '\n')
      .replace(/\\t/g, '\t');
  }
  return s;
}

function parseScalar(token) {
  const s = token.trim();
  if (s === '') return '';
  if ((s[0] === "'" && s.endsWith("'")) || (s[0] === '"' && s.endsWith('"'))) {
    return unquote(s);
  }
  if (s === 'null' || s === '~' || s === '') return null;
  if (s === 'true' || s === 'True') return true;
  if (s === 'false' || s === 'False') return false;
  if (/^-?\d+$/.test(s)) return Number.parseInt(s, 10);
  if (/^-?\d+\.\d+$/.test(s)) return Number.parseFloat(s);
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s; // dates stay strings for our use
  return s;
}

/** Split on commas that are not inside quotes or nested brackets. */
function splitFlow(input) {
  const parts = [];
  let depth = 0;
  let quote = null;
  let current = '';
  for (const ch of input) {
    if (quote) {
      current += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
    } else if (ch === '[' || ch === '{') {
      depth += 1;
      current += ch;
    } else if (ch === ']' || ch === '}') {
      depth -= 1;
      current += ch;
    } else if (ch === ',' && depth === 0) {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim() !== '' || parts.length > 0) parts.push(current);
  return parts.map((p) => p.trim()).filter((p) => p !== '');
}

export function parseFlowValue(text) {
  const s = text.trim();
  if (s.startsWith('[') && s.endsWith(']')) {
    return splitFlow(s.slice(1, -1)).map(parseFlowValue);
  }
  if (s.startsWith('{') && s.endsWith('}')) {
    const obj = {};
    for (const pair of splitFlow(s.slice(1, -1))) {
      const idx = findKeySeparator(pair);
      if (idx === -1) return pair; // malformed; keep as string so caller can warn
      obj[pair.slice(0, idx).trim()] = parseFlowValue(pair.slice(idx + 1));
    }
    return obj;
  }
  return parseScalar(s);
}

/** Find the first ':' that separates key from value (outside quotes/brackets). */
function findKeySeparator(line) {
  let depth = 0;
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') quote = ch;
    else if (ch === '[' || ch === '{') depth += 1;
    else if (ch === ']' || ch === '}') depth -= 1;
    else if (ch === ':' && depth === 0) {
      const next = line[i + 1];
      if (next === undefined || next === ' ' || next === '\t' || next === '\n') return i;
    }
  }
  return -1;
}

class Lines {
  constructor(lines) {
    this.lines = lines;
    this.pos = 0;
  }

  peek() {
    return this.lines[this.pos];
  }

  next() {
    return this.lines[this.pos++];
  }
}

function parseBlock(lines, indent, warnings) {
  const result = {};
  while (true) {
    const line = lines.peek();
    if (line === undefined) break;
    if (line.trim() === '' || line.trim().startsWith('#')) {
      lines.next();
      continue;
    }
    const lineIndent = line.match(/^ */)[0].length;
    if (lineIndent < indent) break;
    if (lineIndent > indent) {
      warnings.push(`unexpected indentation: "${line.trim()}"`);
      lines.next();
      continue;
    }
    if (line.trimStart().startsWith('- ') || line.trim() === '-') {
      // A sequence item at this indentation belongs to an enclosing list,
      // not to this mapping — stop here and let its owner continue.
      break;
    }
    const sep = findKeySeparator(line);
    if (sep === -1) {
      warnings.push(`cannot parse line: "${line.trim()}"`);
      lines.next();
      continue;
    }
    const key = unquote(line.slice(0, sep).trim());
    const valueText = line.slice(sep + 1).trim();
    lines.next();
    if (valueText === '|' || valueText === '|-' || valueText === '>' || valueText === '>-') {
      result[key] = parseLiteralBlock(lines, lineIndent, valueText.startsWith('>'));
      continue;
    }
    if (valueText !== '') {
      result[key] = parseFlowValue(valueText);
      continue;
    }
    // Value on following lines: nested mapping or block sequence.
    const nextLine = firstContentLine(lines);
    if (nextLine === undefined) {
      result[key] = null;
      continue;
    }
    const nextIndent = nextLine.match(/^ */)[0].length;
    if (nextIndent <= lineIndent) {
      result[key] = null;
      continue;
    }
    if (nextLine.trimStart().startsWith('- ') || nextLine.trim() === '-') {
      result[key] = parseSequence(lines, nextIndent, warnings);
    } else {
      result[key] = parseBlock(lines, nextIndent, warnings);
    }
  }
  return result;
}

function firstContentLine(lines) {
  while (true) {
    const line = lines.peek();
    if (line === undefined) return undefined;
    if (line.trim() === '' || line.trim().startsWith('#')) {
      lines.next();
      continue;
    }
    return line;
  }
}

function parseSequence(lines, indent, warnings) {
  const items = [];
  while (true) {
    const save = lines.pos;
    const line = firstContentLine(lines);
    if (line === undefined) break;
    const lineIndent = line.match(/^ */)[0].length;
    const trimmed = line.trimStart();
    if (lineIndent < indent || !(trimmed.startsWith('- ') || trimmed === '-')) {
      lines.pos = save;
      break;
    }
    const itemText = trimmed.slice(1).trim(); // after '-'
    if (itemText === '') {
      lines.next();
      const nextLine = firstContentLine(lines);
      if (nextLine !== undefined && nextLine.match(/^ */)[0].length > lineIndent) {
        items.push(
          nextLine.trimStart().startsWith('- ')
            ? parseSequence(lines, nextLine.match(/^ */)[0].length, warnings)
            : parseBlock(lines, nextLine.match(/^ */)[0].length, warnings),
        );
      } else {
        items.push(null);
      }
      continue;
    }
    const sep = findKeySeparator(itemText);
    if (sep !== -1 && !isQuotedScalar(itemText)) {
      // Compact mapping entry: "- key: value". Rewrite the line in place as
      // an indented mapping line so following keys of the same object are
      // captured naturally by parseBlock.
      const innerIndent = lineIndent + 2;
      lines.lines[lines.pos] = `${' '.repeat(innerIndent)}${itemText}`;
      items.push(parseBlock(lines, innerIndent, warnings));
      continue;
    }
    items.push(parseFlowValue(itemText));
    lines.next();
  }
  return items;
}

function isQuotedScalar(text) {
  const t = text.trim();
  return (
    (t.startsWith("'") && t.endsWith("'") && t.length >= 2) ||
    (t.startsWith('"') && t.endsWith('"') && t.length >= 2)
  );
}

function parseLiteralBlock(lines, parentIndent, folded) {
  const collected = [];
  let contentIndent = null;
  while (true) {
    const line = lines.peek();
    if (line === undefined) break;
    if (line.trim() === '') {
      collected.push('');
      lines.next();
      continue;
    }
    const lineIndent = line.match(/^ */)[0].length;
    if (lineIndent <= parentIndent) break;
    if (contentIndent === null) contentIndent = lineIndent;
    collected.push(folded ? line.trim() : line.slice(Math.min(contentIndent, lineIndent)));
    lines.next();
  }
  // Trim trailing blank entries left over from the separator line.
  while (collected.length > 0 && collected[collected.length - 1] === '') collected.pop();
  return folded ? collected.join(' ') : `${collected.join('\n')}\n`;
}

/**
 * Parse YAML frontmatter text into an object.
 * @param {string} text raw YAML between the --- markers
 * @returns {{ data: Record<string, any>, warnings: string[] }}
 */
export function parseYaml(text) {
  const warnings = [];
  const lines = new Lines(text.replace(/\r\n/g, '\n').split('\n'));
  const first = firstContentLine(lines);
  let data;
  if (first !== undefined && (first.trimStart().startsWith('- ') || first.trim() === '-')) {
    data = parseSequence(lines, first.match(/^ */)[0].length, warnings);
  } else {
    data = parseBlock(lines, 0, warnings);
  }
  return { data: data ?? {}, warnings };
}
