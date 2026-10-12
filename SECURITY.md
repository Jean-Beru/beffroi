# Security policy

Beffroi is an identity provider: a vulnerability here is a vulnerability in every application that trusts it.

## Reporting

Report privately through [GitHub security advisories](https://github.com/beffroi-php/beffroi/security/advisories/new). Do not open a public issue, do not discuss it in a pull request.

You will get an acknowledgement within 72 hours, and a fix or a mitigation plan as fast as the severity requires. Credit is given in the advisory unless you prefer otherwise.

## Scope

Anything in this repository: the identity core, the OAuth 2.0 / OpenID Connect module, the SAML packages, the Symfony bundle, the application, the Docker images and the CI. The security defaults are part of the product and not configuration; a way to bypass one of them without a configuration change is a vulnerability.

## The SAML packages

`beffroi/xml-security` (`src/xml-security`) is the parser boundary of the provider: what its `Core` namespace lets through is what a signature is verified over, and a flaw there is a flaw in every application that trusts a SAML assertion. Its rules are the invariants of `spec/core.md`, `spec/dsig.md` and `spec/enc.md`, section 4; a way to defeat one of them with input, without a code change, is a vulnerability, and so is a refusal message that carries bytes of the input (I-16). Out of scope: a consumer that calls `Dom\XMLDocument::createFromString()`, `getElementById()` or any other call of the table of section 8, which the PHPStan rules of the package exist to prevent.

`beffroi/saml2-model` (`src/saml2-model`) decides, for an identity provider or a service provider, which element of a SAML message a signature had to cover, whose key had to sign it, and whether an assertion is addressed to it, still valid and seen for the first time: a flaw there is an authentication bypass. Its rules are the invariants M-1 to M-17 of `spec/model.md`, section 4; a value read outside what a signature covers (M-1), an assertion accepted without the signature the profile requires (M-2), a key taken from the message (M-3), an assertion accepted for another audience, another endpoint or another request (M-8 to M-10), accepted twice (M-11) or after its window (M-7), and a refusal message that carries a value of the message (M-16) are vulnerabilities. Out of scope: a consumer that calls what its section 8 bans; one that states a wrong expectation (the URL at which a message arrived, the ID of the request it answers), reads with `MetadataReader::readTrusted()` metadata from a channel it does not trust, or implements the replay port with a store that is not atomic or not shared by its workers (section 5.2).

Every security fix of either package ships with a GitHub Security Advisory and a CVE requested for it, so that `composer audit`, Packagist and the advisory databases see it. The existing PHP bricks of this domain fixed canonicalization and authentication-tag flaws without a published advisory; these packages commit to the opposite.

## Supported versions

Until the first tagged release, the default branch only.
