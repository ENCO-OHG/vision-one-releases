import assert from 'node:assert/strict';
import { access, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { atom, buildSite, escape, validate } from '../scripts/build-site.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const config = JSON.parse(await readFile(path.join(root, 'security/site.json'), 'utf8'));
const example = () => ({
  id: 'VO-SA-2026-001',
  title: 'Test fixture only: <unsafe> & "quoted"',
  summary: 'Synthetic test data, not a published vulnerability.',
  published: '2026-10-20T09:00:00Z',
  updated: '2026-10-20T10:00:00Z',
  severity: 'high',
  status: 'resolved',
  affected: [{ product: 'Vision One (test fixture)', versions: 'Example range only', fixedVersions: ['test-fixed'], action: 'Test action' }],
  impact: 'Test impact', remediation: 'Test remediation', workarounds: [],
  references: [{ title: 'Official releases', url: `${config.repository}/releases` }], cves: [],
});

test('the configured public archive validates without publishing fabricated advisories', async () => {
  const advisories = JSON.parse(await readFile(path.join(root, 'security/advisories.json'), 'utf8'));
  assert.doesNotThrow(() => validate(config, advisories));
  assert.equal(config.contact, 'admin@energy-control.it');
});

test('HTML and XML text is escaped', () => {
  assert.equal(escape(`<a href="x">'&`), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;');
});

test('advisory IDs cannot become filesystem paths or be duplicated', () => {
  assert.throws(() => validate(config, [{ ...example(), id: '../../outside' }]), /ID/);
  assert.throws(() => validate(config, [example(), example()]), /duplicate/);
});

test('reference and base URLs reject executable schemes and credentials', () => {
  for (const href of ['javascript:alert(1)', 'http://example.com', 'https://secret:password@example.com']) {
    const advisory = example();
    advisory.references[0].url = href;
    assert.throws(() => validate(config, [advisory]), /HTTPS/);
  }
  assert.throws(() => validate({ ...config, baseUrl: 'https://example.com/path' }, []), /baseUrl/);
});

test('advisory timestamps are real UTC dates and revisions cannot predate publication', () => {
  for (const updated of ['2026-02-30T10:00:00Z', 'not-a-date', '2026-10-19T10:00:00Z']) {
    assert.throws(() => validate(config, [{ ...example(), updated }]), /timestamp|precedes/);
  }
});

test('version applicability, severity, status, CVE and scores require explicit valid data', () => {
  for (const patch of [{ affected: [] }, { severity: 'unknown' }, { status: 'unknown' }, { cves: ['unassigned'] }, { cvss: 11 }, { cvss: -1 }]) {
    assert.throws(() => validate(config, [{ ...example(), ...patch }]));
  }
  assert.doesNotThrow(() => validate(config, [{ ...example(), cvss: 7.5 }]));
});

test('an empty feed is valid structured Atom without invented entries', () => {
  const xml = atom(config, []);
  assert.match(xml, /^<\?xml version="1.0"/);
  assert.match(xml, /xmlns="http:\/\/www.w3.org\/2005\/Atom"/);
  assert.match(xml, /<updated>2026-10-20T00:00:00Z<\/updated>/);
  assert.doesNotMatch(xml, /<entry>/);
});

test('advisory revisions retain their Atom identity and original publication date', () => {
  const first = example();
  const revised = { ...first, updated: '2026-10-21T11:00:00Z' };
  const originalXml = atom(config, [first]);
  const revisedXml = atom(config, [revised]);
  const entryId = (xml) => xml.match(/<entry><id>(.*?)<\/id>/)[1];
  assert.equal(entryId(originalXml), entryId(revisedXml));
  assert.match(revisedXml, /<published>2026-10-20T09:00:00Z<\/published>/);
  assert.match(revisedXml, /<updated>2026-10-21T11:00:00Z<\/updated>/);
  assert.match(revisedXml, /&lt;unsafe&gt; &amp; &quot;quoted&quot;/);
  assert.doesNotMatch(revisedXml, /<unsafe>/);
});

test('the complete empty site includes reporting, feed, privacy and public asset links', async (t) => {
  const output = await mkdtemp(path.join(os.tmpdir(), 'vision-one-security-site-'));
  t.after(() => rm(output, { recursive: true, force: true }));
  await buildSite({ output });
  const html = await readFile(path.join(output, 'index.html'), 'utf8');
  const archive = await readFile(path.join(output, 'advisories/index.html'), 'utf8');
  assert.match(html, /<html lang="en">/);
  assert.match(html, /mailto:admin@energy-control\.it/);
  assert.match(html, /not end-to-end encrypted/);
  assert.match(html, /Email subscription/);
  assert.match(html, /not currently offered/);
  assert.match(html, /No product advisories published yet/);
  assert.match(html, /does not mean.*free of vulnerabilities/);
  assert.match(html, /privacy statement/);
  assert.match(archive, /Security advisory archive/);
  assert.doesNotMatch(html, /<script\b|<iframe\b|<form\b/);
  assert.match(html, /rel="icon" type="image\/svg\+xml"/);
  assert.match(html, /<img src="[^"]*\/assets\/vision-one-logo\.svg"/);
  for (const asset of ['site.css', 'assets/vision-one-logo.svg', 'advisories.atom', 'sitemap.xml', 'robots.txt', '.nojekyll']) {
    await access(path.join(output, asset));
  }
  for (const page of [html, archive]) {
    for (const [, href] of page.matchAll(/href="([^"]+)"/g)) {
      const link = new URL(href, config.baseUrl);
      if (!link.href.startsWith(config.baseUrl)) continue;
      const relative = link.pathname.slice(new URL(config.baseUrl).pathname.length);
      await access(path.join(output, relative.endsWith('/') || !relative ? `${relative}index.html` : relative));
      if (link.hash) {
        const linkedPage = await readFile(path.join(output, relative.endsWith('/') || !relative ? `${relative}index.html` : relative), 'utf8');
        assert.ok(linkedPage.includes(`id="${link.hash.slice(1)}"`), `Missing anchor ${link.hash}`);
      }
    }
  }
});

test('assessed entries generate escaped detail pages and consistent archive/feed ordering', async (t) => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'vision-one-security-advisory-'));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  const source = path.join(workspace, 'source');
  const output = path.join(workspace, 'dist');
  await mkdir(path.join(source, 'security'), { recursive: true });
  await mkdir(path.join(source, 'assets'), { recursive: true });
  const first = example();
  const newest = { ...example(), id: 'VO-SA-2026-002', updated: '2026-10-21T11:00:00Z' };
  await writeFile(path.join(source, 'security/site.json'), JSON.stringify(config));
  await writeFile(path.join(source, 'security/advisories.json'), JSON.stringify([first, newest]));
  await copyFile(path.join(root, 'security/site.css'), path.join(source, 'security/site.css'));
  await copyFile(path.join(root, 'assets/vision-one-logo.svg'), path.join(source, 'assets/vision-one-logo.svg'));
  await buildSite({ source, output });
  const detail = await readFile(path.join(output, 'advisories/VO-SA-2026-001/index.html'), 'utf8');
  assert.match(detail, /&lt;unsafe&gt; &amp; &quot;quoted&quot;/);
  assert.doesNotMatch(detail, /<unsafe>/);
  assert.match(detail, /Example range only/);
  assert.match(detail, /test-fixed/);
  assert.match(detail, /Test remediation/);
  assert.match(detail, /No CVE identifier is listed/);
  const archive = await readFile(path.join(output, 'advisories/index.html'), 'utf8');
  const feed = await readFile(path.join(output, 'advisories.atom'), 'utf8');
  for (const document of [archive, feed]) {
    assert.ok(document.indexOf(newest.id) < document.indexOf(first.id));
  }
});
