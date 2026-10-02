# Security policy

Beffroi is an identity provider: a vulnerability here is a vulnerability in every application that trusts it.

## Reporting

Report privately through [GitHub security advisories](https://github.com/beffroi-php/beffroi/security/advisories/new). Do not open a public issue, do not discuss it in a pull request.

You will get an acknowledgement within 72 hours, and a fix or a mitigation plan as fast as the severity requires. Credit is given in the advisory unless you prefer otherwise.

## Scope

Anything in this repository: the identity core, the OAuth 2.0 / OpenID Connect module, the Symfony bundle, the application, the Docker images and the CI. The security defaults are part of the product and not configuration; a way to bypass one of them without a configuration change is a vulnerability.

## Supported versions

Until the first tagged release, the default branch only.
