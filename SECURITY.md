# Security Policy

## Reporting Security Issues

Do not report security vulnerabilities through public GitHub issues, pull requests, or release comments.

Report suspected security issues privately to **[admin@energy-control.it](mailto:admin@energy-control.it?subject=Vision%20One%20security%20report)**. Include the affected Vision One version and component, installation environment, reproduction steps, observed impact, relevant network/runtime context, and a contact address for follow-up.

Do not include passwords, private keys, active tokens, customer project files or unredacted production data in the initial message. Ordinary email is not end-to-end encrypted. No PGP reporting key is currently published; request an agreed secure transfer method before submitting sensitive evidence. Production testing requires the system owner's authorization.

## Advisories and Subscriptions

The [Vision One Product Security website](https://enco-ohg.github.io/vision-one-releases/) provides the [advisory archive](https://enco-ohg.github.io/vision-one-releases/advisories/) and an [Atom feed](https://enco-ohg.github.io/vision-one-releases/advisories.atom) for newly published and revised advisories. A feed reader is required; no GitHub account is needed. Email subscriptions are not currently offered. GitHub release notifications cover releases, not all advisory revisions.

An empty archive is not evidence that the product or its dependencies are vulnerability-free. Release security audits and product-specific advisories serve different purposes; dependency findings require product-applicability assessment.

## Handling and Disclosure

EN-CO OHG reviews reports, assesses affected versions and product applicability, and coordinates remediation and disclosure with the reporter and relevant parties as appropriate. Validated issues requiring customer action can be published as dated product advisories with remediation or mitigation guidance. Changes retain the advisory identity and update its revision timestamp so feed readers can detect revisions. No fixed response or remediation SLA is promised by this policy.

## Supported Releases

Stable production releases receive priority for security review and remediation. Prerelease builds such as alpha, beta, and release-candidate versions are provided for validation and may be replaced without long-term support.

This policy does not establish a version-specific support lifetime or override customer agreements. Contact EN-CO OHG for installation-specific support and update eligibility.

## Release Assets

Installers are distributed as GitHub Release assets from this repository. Verify that downloads originate from `https://github.com/ENCO-OHG/vision-one-releases/releases` before installing.

Verify published SHA-256 checksums and Windows signatures where provided, and follow the installation's maintenance and backup procedures. The security website deployment does not build, replace or execute installers.
