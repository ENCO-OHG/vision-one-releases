<p align="center">
  <img src="assets/vision-one-icon.png" alt="Vision One" width="96" height="96">
</p>

# Vision One Releases and Product Security

This repository provides the official public Windows installer downloads and product security information for Vision One, a software product by EN-CO OHG.

## Downloads

Current and previous installer packages are available from the [Releases](https://github.com/ENCO-OHG/vision-one-releases/releases) page.

Each release contains the Windows installer asset for the corresponding Vision One version. Use the attached `.exe` file to install Vision One or update an existing installation.

## Release Channels

Stable releases are intended for production use according to the applicable customer agreement and project-specific deployment requirements.

Prerelease versions, including alpha, beta, and release-candidate builds, are provided for validation, acceptance testing, and early deployment preparation. They may change before the final release and should only be used in environments where prerelease software is explicitly accepted.

## Updating Vision One

Vision One includes a manual update check that refers to the GitHub Releases published in this repository. When a newer eligible version is available, the application displays the installer download link.

The installer must be downloaded and executed by an authorized Windows user or administrator. Follow the project-specific maintenance procedure before updating production systems, including backups where required.

## Source Code and Documentation

This repository contains public installer releases and the static Product Security website. It does not contain the Vision One application source code, private installer build configuration, or full product documentation.

For product documentation, operational guidance, licensing information, or project-specific support, contact EN-CO OHG through the official support channels.

## License

Vision One, including the installer packages and release assets provided here, is proprietary EN-CO OHG software. See [LICENSE](LICENSE).

Third-party components included in installer packages remain subject to their own license terms and notices.

## Security

Visit **[Vision One Product Security](https://enco-ohg.github.io/vision-one-releases/)** for advisories, reporting guidance and update information.

- [Security advisory archive](https://enco-ohg.github.io/vision-one-releases/advisories/)
- [Subscribe to new and revised advisories (Atom)](https://enco-ohg.github.io/vision-one-releases/advisories.atom)
- Confidential reports: **[admin@energy-control.it](mailto:admin@energy-control.it)**

Do not report security vulnerabilities through public GitHub issues, pull requests, or release comments. See [SECURITY.md](SECURITY.md) for the reporting policy. Email subscriptions are not currently offered.

### Maintaining the security website

The website uses dependency-free Node.js generation. With Node.js 22 or later:

```sh
npm test
npm run build
```

Generated files are written to ignored `dist/`. Website configuration and reviewed advisory data are under [`security/`](security/); the [maintainer guide](security/README.md) describes the publication process. No application installer or existing release asset is changed by these commands.

The `Publish Product Security Website` workflow validates the site on pull requests and deploys pushes to `main` through GitHub Pages. Repository **Settings → Pages → Source** must be **GitHub Actions**. The initial URL is `https://enco-ohg.github.io/vision-one-releases/`; any custom-domain migration must update `security/site.json` as well.

## Contact

<a href="https://www.energy-control.it/en-co/">
  <img align="right" src="assets/en-co-logo.png" alt="EN-CO OHG" width="320">
</a>

<strong>EN-CO OHG</strong><br>
Handwerkerzone West 3<br>
I-39040 Ratschings/Gasteig, Italy<br>
T +39 0472 738200<br>
F +39 0472 738249<br>
VAT/Tax No. IT00765680210<br>
<a href="mailto:en-co@energy-control.it">en-co@energy-control.it</a>

<br clear="right">
