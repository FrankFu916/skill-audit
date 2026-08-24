import test from 'node:test';
import assert from 'node:assert/strict';
import { splitFrontmatter, parseYaml, parseFlowValue } from '../src/yaml.js';

test('splitFrontmatter: standard block', () => {
  const { raw, body } = splitFrontmatter('---\nname: x\ndescription: y\n---\n\n# Hello\n');
  assert.equal(raw, 'name: x\ndescription: y');
  assert.equal(body, '\n# Hello\n');
});

test('splitFrontmatter: no frontmatter', () => {
  const a = splitFrontmatter('# Just markdown');
  assert.equal(a.raw, null);
  const b = splitFrontmatter('---js\nvar x = 1;\n---');
  assert.equal(b.raw, null); // code fence, not frontmatter
  const c = splitFrontmatter('---\nno closing marker');
  assert.equal(c.raw, null);
});

test('parseYaml: scalars', () => {
  const { data } = parseYaml('a: 1\nb: hello\nc: true\nd: null\ne: 3.14\nf:\n');
  assert.deepEqual(data, { a: 1, b: 'hello', c: true, d: null, e: 3.14, f: null });
});

test('parseYaml: quoted strings with colons', () => {
  const { data } = parseYaml(`a: "key: value"\nb: 'it''s fine'\n`);
  assert.equal(data.a, 'key: value');
  assert.equal(data.b, "it's fine");
});

test('parseYaml: inline flow sequence and mapping', () => {
  const { data } = parseYaml('tags: [a, b, c]\nmeta: {x: 1, y: two}\n');
  assert.deepEqual(data.tags, ['a', 'b', 'c']);
  assert.deepEqual(data.meta, { x: 1, y: 'two' });
});

test('parseYaml: flow sequence containing URLs with colons', () => {
  const { data } = parseYaml('urls: [https://a.com/x, https://b.com/y]\n');
  assert.deepEqual(data.urls, ['https://a.com/x', 'https://b.com/y']);
});

test('parseYaml: block sequence of strings', () => {
  const { data } = parseYaml('tools:\n  - read\n  - write\n  - bash\n');
  assert.deepEqual(data.tools, ['read', 'write', 'bash']);
});

test('parseYaml: block sequence of compact mappings', () => {
  const { data, warnings } = parseYaml('items:\n  - name: one\n    size: 3\n  - name: two\n    size: 7\n');
  assert.deepEqual(
    data.items,
    [
      { name: 'one', size: 3 },
      { name: 'two', size: 7 },
    ],
    `warnings: ${warnings.join('; ')}`,
  );
});

test('parseYaml: nested mapping', () => {
  const { data } = parseYaml('metadata:\n  author: Jane\n  license: MIT\nother: yes\n');
  assert.deepEqual(data.metadata, { author: 'Jane', license: 'MIT' });
  assert.equal(data.other, 'yes');
});

test('parseYaml: folded multiline description (> block)', () => {
  const { data } = parseYaml('description: >\n  line one\n  line two\nname: x\n');
  assert.match(data.description, /line one/);
  assert.match(data.description, /line two/);
});

test('parseYaml: literal block (|) preserves newlines', () => {
  const { data } = parseYaml('text: |\n  alpha\n  beta\nafter: 1\n');
  assert.match(data.text, /alpha\nbeta/);
  assert.equal(data.after, 1);
});

test('parseYaml: real SKILL.md shape', () => {
  const yaml = [
    'name: processing-pdfs',
    'description: >',
    '  Extracts text and tables from PDF files. Use when the user asks',
    '  to process or convert PDF documents.',
    'license: MIT',
    'allowed-tools: [Read, Bash, Write]',
    'metadata:',
    '  version: 1.2',
  ].join('\n');
  const { data, warnings } = parseYaml(yaml);
  assert.equal(warnings.length, 0);
  assert.equal(data.name, 'processing-pdfs');
  assert.match(data.description, /Extracts text and tables/);
  assert.equal(data.license, 'MIT');
  assert.deepEqual(data['allowed-tools'], ['Read', 'Bash', 'Write']);
  assert.deepEqual(data.metadata, { version: 1.2 });
});

test('parseYaml: unparseable lines produce warnings, never throw', () => {
  const { warnings } = parseYaml('just a stray line\nkey: value\n');
  assert.ok(warnings.length >= 1);
});

test('parseFlowValue: deep nesting', () => {
  assert.deepEqual(parseFlowValue('{a: [1, {b: 2}], c: "x, y"}'), {
    a: [1, { b: 2 }],
    c: 'x, y',
  });
});
