# Changelog

## [3.0.0](https://github.com/OSHCO/adfs/compare/v2.0.3...v3.0.0) (2026-11-12)


### ⚠ BREAKING CHANGES

* subclasses of ADFSVerificationService must implement getValidator() and return an ADFSResponseValidator configured with the ADFS token-signing certificate and the relying party identifier. new ADFSResponse() throws SAMLValidationException on malformed input, and a missing username is reported during validation. SHA-1 signatures are rejected unless setAllowSha1(true) is called.

### Features

* verify SAML response signatures and assertion conditions ([1c1b23e](https://github.com/OSHCO/adfs/commit/1c1b23e255f84e514d14f03c915066c75fd52645))

## [2.0.3](https://github.com/OSHCO/adfs/compare/v2.0.2...v2.0.3) (2026-09-24)


### Miscellaneous Chores

* **deps:** loosen version constraints for webfiori packages ([747d14e](https://github.com/OSHCO/adfs/commit/747d14e78ddc8fa1fe6dca14bf9ec9e58a5a8e25))

## [2.0.2](https://github.com/OSHCO/adfs/compare/v2.0.1...v2.0.2) (2026-06-14)


### Miscellaneous Chores

* Updated Dependencies ([e108edf](https://github.com/OSHCO/adfs/commit/e108edffe9a584c5496e00dad388e111a8a7ede3))

## [2.0.1](https://github.com/OSHCO/adfs/compare/v2.0.0...v2.0.1) (2026-05-19)


### Bug Fixes

* ADFSVerificationService.php ([a5978dd](https://github.com/OSHCO/adfs/commit/a5978dd5be09b136e6ffed419bf4f88bfd7c9108))


### Miscellaneous Chores

* Update sonar-project.properties ([ed50a10](https://github.com/OSHCO/adfs/commit/ed50a10d1c6a57b6afbd34c95d01467ece9c56a9))

## [1.3.0](https://github.com/OSHCO/adfs/compare/v1.2.0...v1.3.0) (2026-04-12)


### Miscellaneous Chores

* Merge pull request [#1](https://github.com/OSHCO/adfs/issues/1) from OSHCO/dev ([dc9b1bf](https://github.com/OSHCO/adfs/commit/dc9b1bf09cbaceab56c288ac4e2fff4e375ada46))
* Updated PHP Version ([e50fe52](https://github.com/OSHCO/adfs/commit/e50fe528ef7fcb8519ae7d203959a0c383f28d5f))
