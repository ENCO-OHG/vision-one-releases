import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const escape = (value) => String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);

function httpsUrl(value) {
  if (typeof value !== 'string') throw new Error('An HTTPS URL is required');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Only HTTPS URLs without credentials are accepted');
  return url;
}

function timestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value.replace('Z', '.000Z')) {
    throw new Error(`Invalid UTC timestamp: ${value}`);
  }
  return value;
}

function text(value, field) {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`Missing text: ${field}`);
}

export function validate(config, advisories) {
  text(config.title, 'title');
  const base = httpsUrl(config.baseUrl);
  if (!base.pathname.endsWith('/') || base.search || base.hash) throw new Error('baseUrl must end in / and have no query or fragment');
  httpsUrl(config.repository);
  if (!/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(config.contact)) throw new Error('Invalid contact email');
  timestamp(`${config.reviewed}T00:00:00Z`);
  if (!Array.isArray(advisories)) throw new Error('Advisories must be an array');
  const ids = new Set();
  for (const advisory of advisories) {
    if (!/^VO-SA-\d{4}-\d{3,}$/.test(advisory.id) || ids.has(advisory.id)) throw new Error(`Invalid or duplicate advisory ID: ${advisory.id}`);
    ids.add(advisory.id);
    for (const field of ['title', 'summary', 'impact', 'remediation']) text(advisory[field], field);
    if (!['critical', 'high', 'medium', 'low', 'informational'].includes(advisory.severity)) throw new Error('Invalid severity');
    if (advisory.severitySource !== undefined && !['upstream', 'product'].includes(advisory.severitySource)) throw new Error('Invalid severity source');
    if (advisory.reviewedVersions !== undefined) {
      if (!Array.isArray(advisory.reviewedVersions) || !advisory.reviewedVersions.length) throw new Error('reviewedVersions must be a nonempty version array');
      advisory.reviewedVersions.forEach((version) => text(version, 'reviewed version'));
      if (new Set(advisory.reviewedVersions).size !== advisory.reviewedVersions.length) throw new Error('Duplicate reviewed version');
    }
    if (advisory.assessment !== undefined) {
      if (!Array.isArray(advisory.assessment) || !advisory.assessment.length) throw new Error('assessment must be a nonempty paragraph array');
      advisory.assessment.forEach((paragraph) => text(paragraph, 'assessment paragraph'));
    }
    if (!['open', 'mitigated', 'resolved'].includes(advisory.status)) throw new Error('Invalid status');
    timestamp(advisory.published);
    timestamp(advisory.updated);
    if (advisory.updated < advisory.published) throw new Error('Advisory updated date precedes publication');
    if (!Array.isArray(advisory.affected) || !advisory.affected.length) throw new Error('Affected products are required');
    for (const product of advisory.affected) {
      for (const field of ['product', 'versions', 'action']) text(product[field], field);
      if (!Array.isArray(product.fixedVersions)) throw new Error('fixedVersions must be an array');
      product.fixedVersions.forEach((version) => text(version, 'fixed version'));
    }
    if (!Array.isArray(advisory.workarounds) || !Array.isArray(advisory.references) || !Array.isArray(advisory.cves)) throw new Error('workarounds, references and cves must be arrays');
    advisory.workarounds.forEach((workaround) => text(workaround, 'workaround'));
    advisory.references.forEach((reference) => { text(reference.title, 'reference title'); httpsUrl(reference.url); });
    if (advisory.cves.some((cve) => typeof cve !== 'string' || !/^CVE-\d{4}-\d{4,}$/.test(cve))) throw new Error('Invalid CVE identifier');
    if (advisory.cvss !== undefined && (!Number.isFinite(advisory.cvss) || advisory.cvss < 0 || advisory.cvss > 10)) throw new Error('Invalid CVSS score');
  }
}

const date = (value) => value.slice(0, 10);
const advisoryPath = (advisory) => `advisories/${advisory.id}/`;
const url = (config, relative = '') => new URL(relative, config.baseUrl).href;
const list = (items) => `<ul>${items.map((item) => `<li>${escape(item)}</li>`).join('')}</ul>`;
const severityLabel = (advisory) => `${advisory.severity}${advisory.severitySource === 'upstream' ? ' (upstream)' : ''}`;

function layout(config, title, content, relative = '') {
  const link = (relativePath = '') => escape(url(config, relativePath));
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escape(title)} · EN-CO OHG</title>
<meta name="description" content="Official Vision One product security information, security advisories and confidential vulnerability reporting.">
<meta name="color-scheme" content="light"><link rel="canonical" href="${link(relative)}">
<link rel="icon" type="image/svg+xml" href="${link('assets/vision-one-logo.svg')}"><link rel="stylesheet" href="${link(config.stylesheet)}">
<link rel="alternate" type="application/atom+xml" title="Vision One Security Advisories" href="${link('advisories.atom')}"></head>
<body><a class="skip-link" href="#main">Skip to content</a>
<header class="site-header"><div class="header-inner"><a class="brand" href="${link()}"><img src="${link('assets/vision-one-logo.svg')}" width="40" height="36" alt=""><span>Vision One<small>Product Security</small></span></a>
<nav aria-label="Main navigation"><a href="${link('advisories/')}">Advisories</a><a href="${link('#subscribe')}">Notifications</a><a href="${link('#report')}">Report a vulnerability</a><a href="${escape(config.repository)}/releases">Software releases <span aria-hidden="true">↗</span></a></nav></div></header>
<main id="main">${content}</main>
<footer class="site-footer"><div class="footer-inner"><div class="footer-main">
<div class="footer-brand"><a href="https://www.energy-control.it/en-co/" aria-label="EN-CO OHG company website"><img src="${link('assets/en-co-logo.png')}" width="230" height="71" alt="EN-CO OHG"></a><a class="footer-company-link" href="https://www.energy-control.it/en-co/">Company website <span aria-hidden="true">↗</span></a></div>
<div class="footer-contact"><h2 class="footer-heading">EN-CO OHG</h2><address>Handwerkerzone West 3<br>I-39040 Ratschings/Gasteig, Italy</address><p class="footer-contact-lines"><span>T <a href="tel:+390472738200">+39 0472 738200</a></span><span>F +39 0472 738249</span><span>VAT/Tax No. IT00765680210</span><a href="mailto:en-co@energy-control.it">en-co@energy-control.it</a></p></div>
<div class="footer-resources"><h2 class="footer-heading">Security resources</h2><nav class="footer-navigation" aria-label="Footer navigation"><a href="${link('advisories/')}">Security advisories</a><a href="${link('advisories.atom')}">Advisory feed</a><a href="${escape(config.repository)}/releases">Installer releases</a><a href="${escape(config.repository)}/blob/main/SECURITY.md">Security policy</a><a href="${escape(config.repository)}">GitHub repository</a></nav><p class="footer-security-contact">Security reports<br><a href="mailto:${escape(config.contact)}">${escape(config.contact)}</a></p></div>
</div><div class="footer-bottom"><p class="fine-print">Hosted on GitHub Pages. No analytics, advertising scripts or third-party fonts are used by this site. GitHub may process connection data under its <a href="https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement">privacy statement</a>.</p><p class="footer-copyright">© ${escape(config.reviewed.slice(0, 4))} EN-CO OHG<br><a href="${escape(config.repository)}/blob/main/LICENSE">License &amp; terms</a></p></div></div></footer></body></html>`;
}

function advisoryTable(config, advisories) {
  if (!advisories.length) return `<div class="empty-state"><span class="empty-mark" aria-hidden="true">i</span><div><h3>No product advisories published yet</h3><p>This archive has not yet published a product-specific advisory. An empty archive does not mean that Vision One or its dependencies are free of vulnerabilities. Release security audits may document additional known risks.</p></div></div>`;
  return `<div class="table-scroll" tabindex="0" role="region" aria-label="Security advisories"><table><thead><tr><th>Advisory</th><th>Severity</th><th>Status</th><th>Updated (UTC)</th></tr></thead><tbody>${advisories.map((advisory) => `<tr><td><a href="${escape(url(config, advisoryPath(advisory)))}"><small>${escape(advisory.id)}</small>${escape(advisory.title)}</a>${advisory.reviewedVersions ? `<p class="advisory-versions"><strong>Reviewed versions:</strong> ${advisory.reviewedVersions.map(escape).join(' · ')}</p>` : ''}</td><td><span class="severity ${advisory.severity}">${escape(severityLabel(advisory))}</span></td><td>${escape(advisory.status)}</td><td><time datetime="${advisory.updated}">${date(advisory.updated)}</time></td></tr>`).join('')}</tbody></table></div>`;
}

function home(config, advisories) {
  return layout(config, config.title, `
<section class="hero"><div class="hero-inner"><h1>Vision One Product Security</h1><p class="hero-lead">EN-CO OHG provides security information for Vision One to support the assessment and management of product-related risks. Published advisories describe affected or reviewed versions, available mitigations and recommended actions. This page also provides information on security updates and a confidential channel for reporting suspected vulnerabilities.</p><div class="actions"><a class="button primary" href="#advisories">View advisories</a><a class="button secondary" href="#report">Report a vulnerability</a></div></div></section>
<div class="content"><section id="advisories"><div class="section-heading"><h2>Security advisories</h2><a class="text-link" href="${escape(url(config, 'advisories/'))}">All advisories →</a></div><p>Current assessments and recommended actions, ordered by latest revision. Each advisory identifies its review scope and distinguishes upstream ratings from product-specific findings.</p>${advisoryTable(config, advisories.slice(0, 5))}</section>
<section id="subscribe" class="subscribe-panel"><div><h2>Advisory notifications</h2><p>Subscribe to the Atom feed for new advisories and revisions to existing notices.</p><a class="button primary" href="${escape(url(config, 'advisories.atom'))}">Subscribe via Atom</a><p class="feed-address"><code>${escape(url(config, 'advisories.atom'))}</code></p></div><div class="subscribe-details"><h3>Other notification options</h3><p>GitHub users can watch <a href="${escape(config.repository)}">the release repository</a>. GitHub release notifications announce software releases, not every advisory revision.</p><p><strong>Email subscription:</strong> not currently offered.</p></div></section>
<section id="report"><h2>Report a vulnerability</h2><p>Report suspected security issues privately to EN-CO OHG. Do not submit vulnerability details through public issues, pull requests or release comments.</p><a class="contact-link" href="mailto:${escape(config.contact)}?subject=Vision%20One%20security%20report">${escape(config.contact)}</a><div class="two-column"><div><h3>Information to include</h3>${list(['Vision One version and affected component', 'Installation and network context', 'Reproduction steps and observed impact', 'Known mitigations or relevant references', 'Contact details for follow-up'])}</div><div class="notice"><h3>Submitting sensitive information</h3><p>Exclude credentials, private keys, customer project files and unredacted production data from the initial report. Ordinary email is not end-to-end encrypted. No PGP reporting key is currently published; request an agreed secure transfer method before sending sensitive evidence.</p></div></div></section>
<section id="process"><h2>Vulnerability disclosure process</h2><ol class="process-list"><li><strong>Report review</strong><p>Reports are reviewed and additional technical information is requested where needed.</p></li><li><strong>Impact assessment</strong><p>The review establishes product applicability, affected versions and available mitigations.</p></li><li><strong>Remediation coordination</strong><p>Remediation and disclosure are coordinated with the reporter and relevant parties.</p></li><li><strong>Advisory publication</strong><p>Assessed issues are documented with product status, recommended actions and dated revisions.</p></li></ol></section>
<section id="updates"><h2>Software updates</h2><p>Official releases provide Windows installers, SHA-256 checksums and release-specific security audits where available. Verify download integrity and Windows signatures, and follow the installation's maintenance and backup procedures before updating.</p><a class="text-link" href="${escape(config.repository)}/releases">View software releases →</a></section></div>`);
}

function detail(config, advisory) {
  const affected = advisory.affected.map((product) => `<tr><td>${escape(product.product)}</td><td>${escape(product.versions)}</td><td>${product.fixedVersions.length ? product.fixedVersions.map(escape).join(', ') : 'No fixed version listed'}</td><td>${escape(product.action)}</td></tr>`).join('');
  const assessment = advisory.assessment ? `<h3>Product applicability assessment</h3>${advisory.assessment.map((paragraph) => `<p>${escape(paragraph)}</p>`).join('')}` : '';
  return layout(config, `${advisory.id}: ${advisory.title}`, `
<article class="content advisory-detail">
<a class="text-link" href="${escape(url(config, 'advisories/'))}">← All advisories</a>
<p class="eyebrow">${escape(advisory.id)}</p><h1>${escape(advisory.title)}</h1>
<div class="advisory-meta"><span class="severity ${advisory.severity}">${escape(severityLabel(advisory))}</span><span>Status: ${escape(advisory.status)}</span><span>Published: <time datetime="${advisory.published}">${date(advisory.published)}</time> UTC</span><span>Updated: <time datetime="${advisory.updated}">${date(advisory.updated)}</time> UTC</span>${advisory.cvss !== undefined ? `<span>${advisory.severitySource === 'upstream' ? 'Upstream CVSS' : 'CVSS'} score: ${advisory.cvss}</span>` : ''}</div>
<nav class="advisory-contents" aria-label="On this advisory"><a href="#summary">Summary</a><a href="#product-status">Product status</a><a href="#technical-assessment">Technical assessment</a><a href="#recommended-actions">Recommended actions</a><a href="#references">References</a></nav>
<section id="summary"><h2>Summary</h2><p>${escape(advisory.summary)}</p></section>
<section id="product-status"><h2>Product status</h2><div class="table-scroll" tabindex="0" role="region" aria-label="Affected versions"><table><thead><tr><th>Product</th><th>Affected or reviewed versions</th><th>Fixed versions</th><th>Recommended action</th></tr></thead><tbody>${affected}</tbody></table></div></section>
<section id="technical-assessment"><h2>Technical assessment</h2><h3>Vulnerability and impact</h3><p>${escape(advisory.impact)}</p>${assessment}</section>
<section id="recommended-actions"><h2>Recommended actions</h2><h3>Remediation status</h3><p>${escape(advisory.remediation)}</p><h3>Mitigations and operational guidance</h3>${advisory.workarounds.length ? list(advisory.workarounds) : '<p>No workaround is listed. Follow the remediation guidance above.</p>'}</section>
<section id="references"><h2>References</h2><h3>Vulnerability identifiers</h3>${advisory.cves.length ? list(advisory.cves) : '<p>No CVE identifier is listed.</p>'}<h3>Related resources</h3><ul>${advisory.references.map((reference) => `<li><a href="${escape(reference.url)}">${escape(reference.title)}</a></li>`).join('')}</ul></section>
<p class="muted">Technical enquiries and confidential reports: <a href="mailto:${escape(config.contact)}">${escape(config.contact)}</a>.</p>
</article>`, advisoryPath(advisory));
}

export function atom(config, advisories) {
  const updated = advisories.reduce((latest, advisory) => advisory.updated > latest ? advisory.updated : latest, `${config.reviewed}T00:00:00Z`);
  return `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>${escape(config.title)} Advisories</title><id>${escape(url(config, 'advisories.atom'))}</id><link href="${escape(url(config, 'advisories.atom'))}" rel="self" type="application/atom+xml"/><link href="${escape(url(config, 'advisories/'))}"/><updated>${updated}</updated><author><name>EN-CO OHG</name></author><subtitle>New and revised Vision One product security advisories. An empty feed is not a statement that the product has no vulnerabilities.</subtitle>${advisories.map((advisory) => `<entry><id>${escape(url(config, advisoryPath(advisory)))}</id><title>${escape(`${advisory.id}: ${advisory.title}`)}</title><link href="${escape(url(config, advisoryPath(advisory)))}"/><published>${advisory.published}</published><updated>${advisory.updated}</updated><category term="${advisory.severity}" label="${escape(severityLabel(advisory))}"/><summary type="text">${escape(advisory.summary)}</summary></entry>`).join('')}</feed>\n`;
}

export async function buildSite({ source = root, output = path.join(root, 'dist') } = {}) {
  const config = JSON.parse(await readFile(path.join(source, 'security/site.json'), 'utf8'));
  const advisories = JSON.parse(await readFile(path.join(source, 'security/advisories.json'), 'utf8'));
  validate(config, advisories);
  const css = await readFile(path.join(source, 'security/site.css'));
  const stylesheet = `site.${createHash('sha256').update(css).digest('hex').slice(0, 12)}.css`;
  const pageConfig = { ...config, stylesheet };
  advisories.sort((a, b) => b.updated.localeCompare(a.updated) || a.id.localeCompare(b.id));
  await mkdir(path.join(output, 'advisories'), { recursive: true });
  await mkdir(path.join(output, 'assets'), { recursive: true });
  await writeFile(path.join(output, 'index.html'), home(pageConfig, advisories));
  await writeFile(path.join(output, 'advisories/index.html'), layout(pageConfig, 'Security advisory archive', `<div class="content archive"><p class="eyebrow">Vision One Product Security</p><h1>Security advisory archive</h1><p>All published product advisories, newest revision first. Each entry lists publication and revision dates in UTC.</p>${advisoryTable(config, advisories)}<p><a class="text-link" href="${escape(url(config, 'advisories.atom'))}">Subscribe to the Atom feed →</a></p></div>`, 'advisories/'));
  for (const advisory of advisories) {
    const dir = path.join(output, advisoryPath(advisory));
    await mkdir(dir, { recursive: true });
    await writeFile(path.join(dir, 'index.html'), detail(pageConfig, advisory));
  }
  await writeFile(path.join(output, 'advisories.atom'), atom(config, advisories));
  await writeFile(path.join(output, stylesheet), css);
  await copyFile(path.join(source, 'assets/vision-one-logo.svg'), path.join(output, 'assets/vision-one-logo.svg'));
  await copyFile(path.join(source, 'assets/en-co-logo.png'), path.join(output, 'assets/en-co-logo.png'));
  await writeFile(path.join(output, '.nojekyll'), '');
  await writeFile(path.join(output, 'robots.txt'), `User-agent: *\nAllow: /\nSitemap: ${url(config, 'sitemap.xml')}\n`);
  const pages = ['', 'advisories/', ...advisories.map(advisoryPath)];
  await writeFile(path.join(output, 'sitemap.xml'), `<?xml version="1.0" encoding="utf-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${pages.map((relative) => `<url><loc>${escape(url(config, relative))}</loc></url>`).join('')}</urlset>\n`);
  return { config, advisories, stylesheet };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const { advisories } = await buildSite();
  console.log(`Built Product Security website with ${advisories.length} published advisories.`);
}
