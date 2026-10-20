import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
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

function layout(config, title, content, relative = '') {
  const link = (relativePath = '') => escape(url(config, relativePath));
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escape(title)} · EN-CO OHG</title>
<meta name="description" content="Official Vision One product security information, security advisories and confidential vulnerability reporting.">
<meta name="color-scheme" content="light"><link rel="canonical" href="${link(relative)}">
<link rel="icon" href="${link('assets/vision-one-icon.png')}"><link rel="stylesheet" href="${link('site.css')}">
<link rel="alternate" type="application/atom+xml" title="Vision One Security Advisories" href="${link('advisories.atom')}"></head>
<body><a class="skip-link" href="#main">Skip to content</a>
<header class="site-header"><div class="header-inner"><a class="brand" href="${link()}"><img src="${link('assets/vision-one-icon.png')}" width="40" height="40" alt=""><span>Vision One<small>Product Security</small></span></a>
<nav aria-label="Main navigation"><a href="${link('advisories/')}">Advisories</a><a href="${link('#subscribe')}">Subscribe</a><a href="${link('#report')}">Report a vulnerability</a><a href="${escape(config.repository)}/releases">Downloads <span aria-hidden="true">↗</span></a></nav></div></header>
<main id="main">${content}</main>
<footer><div><strong>EN-CO OHG</strong><p>Official security information for Vision One.</p><a href="https://www.energy-control.it/en-co/">Company website</a> · <a href="${escape(config.repository)}">GitHub repository</a> · <a href="${escape(config.repository)}/blob/main/SECURITY.md">Security policy</a></div>
<p class="fine-print">Hosted on GitHub Pages. No analytics, advertising scripts or third-party fonts are used by this site. GitHub may process connection data under its <a href="https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement">privacy statement</a>. Software and associated documentation remain subject to the repository license.</p></footer></body></html>`;
}

function advisoryTable(config, advisories) {
  if (!advisories.length) return `<div class="empty-state"><span class="empty-mark" aria-hidden="true">i</span><div><h3>No product advisories published yet</h3><p>This archive has not yet published a product-specific advisory. An empty archive does not mean that Vision One or its dependencies are free of vulnerabilities. Release security audits may document additional known risks.</p></div></div>`;
  return `<div class="table-scroll" tabindex="0" role="region" aria-label="Security advisories"><table><thead><tr><th>Advisory</th><th>Severity</th><th>Status</th><th>Updated (UTC)</th></tr></thead><tbody>${advisories.map((advisory) => `<tr><td><a href="${escape(url(config, advisoryPath(advisory)))}"><small>${escape(advisory.id)}</small>${escape(advisory.title)}</a></td><td><span class="severity ${advisory.severity}">${escape(advisory.severity)}</span></td><td>${escape(advisory.status)}</td><td><time datetime="${advisory.updated}">${date(advisory.updated)}</time></td></tr>`).join('')}</tbody></table></div>`;
}

function home(config, advisories) {
  return layout(config, config.title, `
<section class="hero"><div class="hero-inner"><p class="eyebrow">EN-CO OHG · Product Security</p><h1>Security information.<br><span>Clear actions.</span></h1><p class="hero-lead">Official security advisories, update guidance and a confidential reporting channel for Vision One.</p><div class="actions"><a class="button primary" href="#advisories">Security advisories <span aria-hidden="true">↓</span></a><a class="button secondary" href="#report">Report a vulnerability</a></div><p class="hero-note">Public information · No account required</p></div><div class="hero-aside" aria-hidden="true"><div class="shield">✓</div><span>Vision One</span><small>Product Security</small></div></section>
<div class="content"><section id="advisories"><div class="section-heading"><div><p class="eyebrow">Assess &amp; act</p><h2>Security advisories</h2></div><a class="text-link" href="${escape(url(config, 'advisories/'))}">Full advisory archive →</a></div><p>Published advisories describe assessed product impact, affected versions and recommended actions. A vulnerable dependency alone does not establish that a product is exploitable.</p>${advisoryTable(config, advisories.slice(0, 5))}<p class="muted">Initial archive review: ${escape(config.reviewed)}. Advisory publication and revision dates are recorded separately.</p></section>
<section id="subscribe" class="subscribe-panel"><div><p class="eyebrow">Stay informed</p><h2>Subscribe to security updates</h2><p>Add the Atom feed to a feed reader to follow newly published and revised advisories. No GitHub account is required.</p><a class="button primary" href="${escape(url(config, 'advisories.atom'))}">Open advisory feed ↗</a><p class="feed-address"><code>${escape(url(config, 'advisories.atom'))}</code></p></div><div class="subscribe-details"><h3>GitHub notifications</h3><p>GitHub users can watch <a href="${escape(config.repository)}">this repository</a> for repository activity. Release notifications cover software releases; they are not a dedicated subscription to security-advisory revisions.</p><p><strong>Email subscription:</strong> not currently offered. The reporting address below is not a mailing-list registration service.</p></div></section>
<section id="report"><p class="eyebrow">Confidential reporting</p><h2>Report a suspected vulnerability</h2><p>Send security reports privately to EN-CO OHG. Do not disclose unassessed vulnerabilities through public issues, pull requests or release comments.</p><a class="contact-link" href="mailto:${escape(config.contact)}?subject=Vision%20One%20security%20report">${escape(config.contact)}</a><div class="two-column"><div><h3>Useful report details</h3>${list(['Affected Vision One version and component', 'Installation and network context', 'Reproduction steps and observed impact', 'Suggested mitigations, if known', 'A contact address for coordinated follow-up'])}</div><div class="notice"><h3>Protect operational data</h3><p>Do not send passwords, private keys, live access tokens, customer project files or unredacted production data in the initial email. Ordinary email is not end-to-end encrypted. No PGP reporting key is currently published; request an agreed secure transfer method before sending sensitive evidence.</p></div></div></section>
<section id="process"><p class="eyebrow">Handling &amp; disclosure</p><h2>How security reports are handled</h2><ol class="process-list"><li><strong>Review</strong><p>EN-CO OHG reviews the report and may request further evidence or environmental details.</p></li><li><strong>Assess</strong><p>Product applicability, affected versions, exposure and practical mitigations are evaluated.</p></li><li><strong>Coordinate</strong><p>Remediation and disclosure are coordinated with the reporter and relevant parties as appropriate.</p></li><li><strong>Publish</strong><p>Validated issues requiring customer action can be published here with version-specific guidance and dated revisions.</p></li></ol><p class="muted">This describes the intended handling process, not a guaranteed response or remediation time. Do not test production systems without the system owner's authorization.</p></section>
<section id="updates" class="two-column"><div><p class="eyebrow">Updates &amp; operating guidance</p><h2>Use official releases</h2><p>Use the official release page for signed Windows installers, published SHA-256 checksums and release-specific security audits where provided. Apply updates under the site's maintenance and backup procedures; verify download integrity and Windows signatures before installation.</p><a class="text-link" href="${escape(config.repository)}/releases">Vision One releases →</a></div><div class="notice"><h3>Support and scope</h3><p>Stable production releases receive priority for security review and remediation. Prereleases are intended for validation and may be replaced without long-term support. This page does not establish a version-specific support lifetime; contractual terms and installation requirements remain applicable.</p><p>An audit is a release assessment, not a guarantee of vulnerability-free operation or a substitute for a product advisory. OT network segmentation and site-specific security controls remain necessary.</p></div></section></div>`);
}

function detail(config, advisory) {
  const affected = advisory.affected.map((product) => `<tr><td>${escape(product.product)}</td><td>${escape(product.versions)}</td><td>${product.fixedVersions.length ? product.fixedVersions.map(escape).join(', ') : 'No fixed version listed'}</td><td>${escape(product.action)}</td></tr>`).join('');
  return layout(config, `${advisory.id}: ${advisory.title}`, `<article class="content advisory-detail"><a class="text-link" href="${escape(url(config, 'advisories/'))}">← All advisories</a><p class="eyebrow">${escape(advisory.id)}</p><h1>${escape(advisory.title)}</h1><div class="advisory-meta"><span class="severity ${advisory.severity}">${escape(advisory.severity)}</span><span>Status: ${escape(advisory.status)}</span><span>Published: ${date(advisory.published)} UTC</span><span>Updated: ${date(advisory.updated)} UTC</span>${advisory.cvss !== undefined ? `<span>CVSS score: ${advisory.cvss}</span>` : ''}</div><p class="lead">${escape(advisory.summary)}</p><section><h2>Affected products and versions</h2><div class="table-scroll" tabindex="0" role="region" aria-label="Affected versions"><table><thead><tr><th>Product</th><th>Affected versions</th><th>Fixed versions</th><th>Action</th></tr></thead><tbody>${affected}</tbody></table></div></section><section><h2>Impact</h2><p>${escape(advisory.impact)}</p></section><section><h2>Remediation</h2><p>${escape(advisory.remediation)}</p></section><section><h2>Workarounds and mitigations</h2>${advisory.workarounds.length ? list(advisory.workarounds) : '<p>No workaround is listed. Follow the remediation guidance above.</p>'}</section><section><h2>Identifiers and references</h2>${advisory.cves.length ? list(advisory.cves) : '<p>No CVE identifier is listed.</p>'}<ul>${advisory.references.map((reference) => `<li><a href="${escape(reference.url)}">${escape(reference.title)}</a></li>`).join('')}</ul></section><p class="muted">Follow site maintenance procedures before applying changes to an operational installation. Questions and confidential reports: <a href="mailto:${escape(config.contact)}">${escape(config.contact)}</a>.</p></article>`, advisoryPath(advisory));
}

export function atom(config, advisories) {
  const updated = advisories.reduce((latest, advisory) => advisory.updated > latest ? advisory.updated : latest, `${config.reviewed}T00:00:00Z`);
  return `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>${escape(config.title)} Advisories</title><id>${escape(url(config, 'advisories.atom'))}</id><link href="${escape(url(config, 'advisories.atom'))}" rel="self" type="application/atom+xml"/><link href="${escape(url(config, 'advisories/'))}"/><updated>${updated}</updated><author><name>EN-CO OHG</name></author><subtitle>New and revised Vision One product security advisories. An empty feed is not a statement that the product has no vulnerabilities.</subtitle>${advisories.map((advisory) => `<entry><id>${escape(url(config, advisoryPath(advisory)))}</id><title>${escape(`${advisory.id}: ${advisory.title}`)}</title><link href="${escape(url(config, advisoryPath(advisory)))}"/><published>${advisory.published}</published><updated>${advisory.updated}</updated><category term="${advisory.severity}"/><summary type="text">${escape(advisory.summary)}</summary></entry>`).join('')}</feed>\n`;
}

export async function buildSite({ source = root, output = path.join(root, 'dist') } = {}) {
  const config = JSON.parse(await readFile(path.join(source, 'security/site.json'), 'utf8'));
  const advisories = JSON.parse(await readFile(path.join(source, 'security/advisories.json'), 'utf8'));
  validate(config, advisories);
  advisories.sort((a, b) => b.updated.localeCompare(a.updated) || a.id.localeCompare(b.id));
  await mkdir(path.join(output, 'advisories'), { recursive: true });
  await mkdir(path.join(output, 'assets'), { recursive: true });
  await writeFile(path.join(output, 'index.html'), home(config, advisories));
  await writeFile(path.join(output, 'advisories/index.html'), layout(config, 'Security advisory archive', `<div class="content archive"><p class="eyebrow">Vision One Product Security</p><h1>Security advisory archive</h1><p>All published product advisories, newest revision first. Each entry lists publication and revision dates in UTC.</p>${advisoryTable(config, advisories)}<p><a class="text-link" href="${escape(url(config, 'advisories.atom'))}">Subscribe to the Atom feed →</a></p></div>`, 'advisories/'));
  for (const advisory of advisories) {
    const dir = path.join(output, advisoryPath(advisory));
    await mkdir(dir, { recursive: true });
    await writeFile(path.join(dir, 'index.html'), detail(config, advisory));
  }
  await writeFile(path.join(output, 'advisories.atom'), atom(config, advisories));
  await copyFile(path.join(source, 'security/site.css'), path.join(output, 'site.css'));
  await copyFile(path.join(source, 'assets/vision-one-icon.png'), path.join(output, 'assets/vision-one-icon.png'));
  await writeFile(path.join(output, '.nojekyll'), '');
  await writeFile(path.join(output, 'robots.txt'), `User-agent: *\nAllow: /\nSitemap: ${url(config, 'sitemap.xml')}\n`);
  const pages = ['', 'advisories/', ...advisories.map(advisoryPath)];
  await writeFile(path.join(output, 'sitemap.xml'), `<?xml version="1.0" encoding="utf-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${pages.map((relative) => `<url><loc>${escape(url(config, relative))}</loc></url>`).join('')}</urlset>\n`);
  return { config, advisories };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const { advisories } = await buildSite();
  console.log(`Built Product Security website with ${advisories.length} published advisories.`);
}
