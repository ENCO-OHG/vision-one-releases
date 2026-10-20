import assert from 'node:assert/strict';
import { access, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { atom, buildSite, escape, validate, validateStatus } from '../scripts/build-site.mjs';

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

async function fixtureSite(t, advisories, cssSuffix = '') {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'vision-one-security-site-'));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  const source = path.join(workspace, 'source');
  const output = path.join(workspace, 'dist');
  await mkdir(path.join(source, 'security'), { recursive: true });
  await mkdir(path.join(source, 'assets'), { recursive: true });
  await writeFile(path.join(source, 'security/site.json'), JSON.stringify(config));
  await writeFile(path.join(source, 'security/advisories.json'), JSON.stringify(advisories));
  await copyFile(path.join(root, 'security/status.json'), path.join(source, 'security/status.json'));
  await copyFile(path.join(root, 'security/site.css'), path.join(source, 'security/site.css'));
  if (cssSuffix) {
    const cssPath = path.join(source, 'security/site.css');
    await writeFile(cssPath, (await readFile(cssPath, 'utf8')) + cssSuffix);
  }
  await copyFile(path.join(root, 'assets/vision-one-logo.svg'), path.join(source, 'assets/vision-one-logo.svg'));
  await copyFile(path.join(root, 'assets/en-co-logo.png'), path.join(source, 'assets/en-co-logo.png'));
  await buildSite({ source, output });
  return output;
}

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
  assert.doesNotThrow(() => validate(config, [{ ...example(), severity: 'not-rated' }]));
});

test('review snapshots require a valid date and nonnegative audit-entry counts', () => {
  const review = { reviewedAt: '2026-10-20T13:23:33Z', productVersion: '27.2.2', checks: [{ component: 'Test', scope: 'npm only', entries: 0, assessment: 'Scoped result' }] };
  assert.doesNotThrow(() => validateStatus(review));
  assert.throws(() => validateStatus({ ...review, reviewedAt: 'invalid' }));
  assert.throws(() => validateStatus({ ...review, checks: [] }));
  assert.throws(() => validateStatus({ ...review, checks: [{ ...review.checks[0], entries: -1 }] }));
  assert.throws(() => validateStatus({ ...review, checks: [{ ...review.checks[0], entries: 1.5 }] }));
});

test('rating sources and assessment paragraphs cannot contain arbitrary structures', () => {
  for (const patch of [{ severitySource: '<script>' }, { assessment: 'not an array' }, { assessment: [] }, { assessment: [''] }, { assessment: [null] }]) {
    assert.throws(() => validate(config, [{ ...example(), ...patch }]));
  }
  assert.doesNotThrow(() => validate(config, [{ ...example(), severitySource: 'upstream', assessment: ['Reviewed scope'] }]));
});

test('reviewed versions require explicit nonempty distinct labels', () => {
  for (const reviewedVersions of ['27.2.2', [], [''], [null], ['27.2.2', '27.2.2']]) {
    assert.throws(() => validate(config, [{ ...example(), reviewedVersions }]));
  }
  assert.doesNotThrow(() => validate(config, [{ ...example(), reviewedVersions: ['27.2.1', '27.2.2'] }]));
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
  const output = await fixtureSite(t, []);
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
  assert.match(html, /assets\/en-co-logo\.png/);
  assert.match(html, /Handwerkerzone West 3/);
  assert.match(html, /I-39040 Ratschings\/Gasteig, Italy/);
  assert.match(html, /tel:\+390472738200/);
  assert.match(html, /F \+39 0472 738249/);
  assert.match(html, /VAT\/Tax No\. IT00765680210/);
  assert.match(html, /mailto:en-co@energy-control\.it/);
  assert.match(html, /aria-label="Footer navigation"/);
  assert.doesNotMatch(html, /Support and scope|This describes the intended handling process/);
  assert.match(html, /<h1>Vision One Product Security<\/h1>/);
  assert.match(html, /EN-CO OHG provides security information for Vision One to support the assessment and management of product-related risks/);
  assert.match(html, /a confidential channel for reporting suspected vulnerabilities/);
  const footerBrand = html.match(/<div class="footer-brand">([\s\S]*?)<\/div>/)?.[1];
  assert.ok(footerBrand);
  assert.doesNotMatch(footerBrand, /Vision One Product Security/);
  assert.match(footerBrand, /assets\/en-co-logo\.png/);
  assert.match(footerBrand, /Company website/);
  assert.match(html, /<h2>Advisory notifications<\/h2>/);
  assert.match(html, /<h2>Vulnerability disclosure process<\/h2>/);
  assert.match(html, /<h2>Software updates<\/h2>/);
  assert.doesNotMatch(html, /Clear actions|Assess &amp; act|Stay informed|class="shield"|Public information · No account required|No GitHub account is required/);
  assert.match(archive, /Security advisory archive/);
  assert.doesNotMatch(html, /<script\b|<iframe\b|<form\b/);
  assert.match(html, /rel="icon" type="image\/svg\+xml"/);
  assert.match(html, /<img src="[^"]*\/assets\/vision-one-logo\.svg"/);
  const stylesheet = html.match(/site\.[a-f0-9]{12}\.css/)?.[0];
  assert.ok(stylesheet, 'The stylesheet must use a content-versioned filename');
  for (const asset of [stylesheet, 'assets/vision-one-logo.svg', 'assets/en-co-logo.png', 'advisories.atom', 'sitemap.xml', 'robots.txt', '.nojekyll']) {
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

test('CSS content changes invalidate cached stylesheets consistently across all pages', async (t) => {
  const first = await fixtureSite(t, [example()]);
  const repeated = await fixtureSite(t, [example()]);
  const changed = await fixtureSite(t, [example()], '\n/* New layout revision */\n');
  const stylesheetIn = async (output, relative = 'index.html') => {
    const html = await readFile(path.join(output, relative), 'utf8');
    return html.match(/site\.[a-f0-9]{12}\.css/)?.[0];
  };
  const originalName = await stylesheetIn(first);
  assert.ok(originalName);
  assert.equal(await stylesheetIn(repeated), originalName);
  const changedName = await stylesheetIn(changed);
  assert.ok(changedName);
  assert.notEqual(changedName, originalName);
  for (const relative of ['index.html', 'advisories/index.html', 'advisories/VO-SA-2026-001/index.html', 'security-status/index.html', 'deployment/index.html']) {
    assert.equal(await stylesheetIn(changed, relative), changedName);
  }
  assert.match(await readFile(path.join(changed, changedName), 'utf8'), /New layout revision/);
});

test('the SMTP notice gives a scoped configuration procedure without inventing a fix or score', async (t) => {
  const output = await mkdtemp(path.join(os.tmpdir(), 'vision-one-smtp-notice-'));
  t.after(() => rm(output, { recursive: true, force: true }));
  const { advisories } = await buildSite({ output });
  const notice = advisories.find((advisory) => advisory.id === 'VO-SA-2026-002');
  assert.ok(notice);
  assert.equal(notice.severity, 'not-rated');
  assert.equal(notice.cvss, undefined);
  assert.equal(notice.status, 'open');
  assert.deepEqual(notice.cves, []);
  assert.deepEqual(notice.reviewedVersions, ['27.2.0', '27.2.1', '27.2.2']);
  assert.ok(notice.affected.every((product) => product.fixedVersions.length === 0));
  const detail = await readFile(path.join(output, 'advisories/VO-SA-2026-002/index.html'), 'utf8');
  assert.match(detail, /Not rated/);
  assert.match(detail, /No fixed version listed/);
  assert.match(detail, /does not itself require an encrypted connection or prevent STARTTLS downgrade/);
  assert.match(detail, /lacking the explicit-choice marker/);
  assert.match(detail, /Settings &gt; Mail and enable TLS certificate verification/);
  assert.match(detail, /global technical-diagnostics setting, not a one-off test address/);
  assert.match(detail, /restore the intended configuration/);
  assert.match(detail, /do not validate a customer&#39;s relay/);
  const feed = await readFile(path.join(output, 'advisories.atom'), 'utf8');
  assert.match(feed, /VO-SA-2026-002/);
  assert.match(feed, /term="not-rated" label="Not rated"/);
});

test('security status separates the dated npm snapshot, open notices and build-tool scope', async (t) => {
  const output = await mkdtemp(path.join(os.tmpdir(), 'vision-one-security-status-'));
  t.after(() => rm(output, { recursive: true, force: true }));
  const { review } = await buildSite({ output });
  const page = await readFile(path.join(output, 'security-status/index.html'), 'utf8');
  assert.match(page, /<h1>Security status<\/h1>/);
  assert.ok(page.includes(`datetime="${review.reviewedAt}"`));
  assert.ok(page.includes(escape(review.productVersion)));
  assert.match(page, /VO-SA-2026-001/);
  assert.match(page, /VO-SA-2026-002/);
  assert.match(page, /eight moderate npm package entries for this one upstream advisory/);
  assert.match(page, /does not prove that every packaged file is unaffected/);
  assert.match(page, /not a live vulnerability monitor/);
  assert.match(page, /not a comprehensive code audit/);
  assert.match(page, /native libraries/);
  assert.equal(review.checks.find((check) => check.component === 'Electron build tooling').entries, 8);
  for (const check of review.checks) {
    assert.ok(page.includes(escape(check.scope)));
    assert.ok(page.includes(escape(check.assessment)));
  }
  const emptyStatusOutput = await fixtureSite(t, []);
  const emptyStatus = await readFile(path.join(emptyStatusOutput, 'security-status/index.html'), 'utf8');
  assert.match(emptyStatus, /No open or mitigated notices are listed/);
  assert.doesNotMatch(emptyStatus, /No product advisories published yet/);
});

test('deployment guidance and every generated page use working internal links', async (t) => {
  const output = await mkdtemp(path.join(os.tmpdir(), 'vision-one-deployment-guidance-'));
  t.after(() => rm(output, { recursive: true, force: true }));
  const { advisories } = await buildSite({ output });
  const deployment = await readFile(path.join(output, 'deployment/index.html'), 'utf8');
  assert.match(deployment, /<h1>Secure deployment guidance<\/h1>/);
  assert.match(deployment, /selected operating data are intentionally readable without login/);
  assert.match(deployment, /Vision One Operators/);
  assert.match(deployment, /does not itself require TLS/);
  assert.match(deployment, /does not itself verify the downloaded file/);
  assert.match(deployment, /databases and WALs/);
  const pages = ['index.html', 'advisories/index.html', 'security-status/index.html', 'deployment/index.html', ...advisories.map((advisory) => `advisories/${advisory.id}/index.html`)];
  for (const relative of pages) {
    const html = await readFile(path.join(output, relative), 'utf8');
    for (const [, href] of html.matchAll(/href="([^"]+)"/g)) {
      const link = new URL(href, new URL(relative, config.baseUrl));
      if (!link.href.startsWith(config.baseUrl)) continue;
      const file = link.pathname.slice(new URL(config.baseUrl).pathname.length);
      const target = path.join(output, !file || file.endsWith('/') ? `${file}index.html` : file);
      await access(target);
      if (link.hash) assert.ok((await readFile(target, 'utf8')).includes(`id="${link.hash.slice(1)}"`));
    }
  }
  const sitemap = await readFile(path.join(output, 'sitemap.xml'), 'utf8');
  assert.match(sitemap, /security-status\//);
  assert.match(sitemap, /deployment\//);
});

test('assessed entries generate escaped detail pages and consistent archive/feed ordering', async (t) => {
  const first = example();
  const newest = { ...example(), id: 'VO-SA-2026-002', updated: '2026-10-21T11:00:00Z' };
  const output = await fixtureSite(t, [first, newest]);
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

test('upstream severity stays explicitly qualified on every publication surface', async (t) => {
  const advisory = { ...example(), severitySource: 'upstream', cvss: 8.7, assessment: ['Scope <unsafe> & limitations'] };
  const output = await fixtureSite(t, [advisory]);
  const detail = await readFile(path.join(output, `advisories/${advisory.id}/index.html`), 'utf8');
  const home = await readFile(path.join(output, 'index.html'), 'utf8');
  const archive = await readFile(path.join(output, 'advisories/index.html'), 'utf8');
  const feed = await readFile(path.join(output, 'advisories.atom'), 'utf8');
  for (const page of [detail, home, archive]) assert.match(page, /high \(upstream\)/);
  assert.match(detail, /Upstream CVSS score: 8.7/);
  assert.match(detail, /Product applicability assessment/);
  assert.match(detail, /Scope &lt;unsafe&gt; &amp; limitations/);
  assert.doesNotMatch(detail, /<unsafe>/);
  assert.match(feed, /label="high \(upstream\)"/);
});

test('reviewed version summaries are escaped and displayed below the linked title', async (t) => {
  const output = await fixtureSite(t, [{ ...example(), reviewedVersions: ['27.2.1', '<reviewed>'] }]);
  for (const relative of ['index.html', 'advisories/index.html']) {
    const html = await readFile(path.join(output, relative), 'utf8');
    assert.match(html, /<\/a><p class="advisory-versions"><strong>Reviewed versions:<\/strong> 27\.2\.1 · &lt;reviewed&gt;<\/p>/);
    assert.doesNotMatch(html, /<reviewed>/);
  }
});

test('the node-forge notice retains an open assessment and does not invent a fixed version', async (t) => {
  const output = await mkdtemp(path.join(os.tmpdir(), 'vision-one-security-notice-'));
  t.after(() => rm(output, { recursive: true, force: true }));
  const { advisories } = await buildSite({ output });
  const notice = advisories.find((advisory) => advisory.id === 'VO-SA-2026-001');
  assert.ok(notice);
  assert.equal(notice.status, 'open');
  assert.equal(notice.severitySource, 'upstream');
  assert.deepEqual(notice.reviewedVersions, ['27.2.0', '27.2.1', '27.2.2']);
  assert.deepEqual(notice.cves, ['CVE-2026-85393']);
  assert.ok(notice.affected.every((product) => product.fixedVersions.length === 0));
  assert.match(notice.affected[0].versions, /27\.2\.0, 27\.2\.1 and 27\.2\.2/);
  assert.match(notice.summary, /Remote exploitability.*has not been established/);
  assert.match(notice.impact, /not a Vision One-specific/);
  const detail = await readFile(path.join(output, 'advisories/VO-SA-2026-001/index.html'), 'utf8');
  assert.match(detail, /No fixed version listed/);
  assert.match(detail, /Status: open/);
  assert.match(detail, /No Vision One-specific CVSS score is assigned/);
  assert.match(detail, /csr.verify\(\)/);
  assert.match(detail, /literal-import scan/);
  assert.match(detail, /not a general security guarantee/);
  assert.match(detail, /aria-label="On this advisory"/);
  const sections = ['summary', 'product-status', 'technical-assessment', 'recommended-actions', 'references'];
  let previous = -1;
  for (const section of sections) {
    assert.ok(detail.includes(`href="#${section}"`));
    const position = detail.indexOf(`<section id="${section}">`);
    assert.ok(position > previous, `Missing or unordered section ${section}`);
    previous = position;
  }
  for (const paragraph of [notice.summary, notice.impact, notice.remediation, ...notice.assessment, ...notice.workarounds]) {
    assert.ok(detail.includes(escape(paragraph)), 'The presentation must retain the published technical assessment');
  }
  const feed = await readFile(path.join(output, 'advisories.atom'), 'utf8');
  assert.equal((feed.match(/<entry>/g) ?? []).length, advisories.length);
  assert.match(feed, /VO-SA-2026-001/);
  assert.doesNotMatch(detail, /No product advisories published yet/);
  for (const relative of ['index.html', 'advisories/index.html']) {
    const html = await readFile(path.join(output, relative), 'utf8');
    assert.match(html, /Reviewed versions:<\/strong> 27\.2\.0 · 27\.2\.1 · 27\.2\.2/);
  }
});
