<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function base64_encode;
use Beffroi\Saml2\Bindings\Internal\Reception;
use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Bindings\Tests\Support\FrozenClock;
use Beffroi\Saml2\Bindings\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Bindings\Tests\Unit\Internal\CodecFixtures;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use DateTimeImmutable;

trait ReceptionFixtures
{
    use CodecFixtures;

    public const string AUTHN_REQUEST = 'behaviour/authn-request-unsigned.xml';

    public const string LOGOUT_REQUEST = 'behaviour/logout-request-written-for-http-redirect.xml';

    public const string LOGOUT_RESPONSE = 'behaviour/logout-response-written-for-http-redirect.xml';

    public const string RESPONSE = 'behaviour/response-signed-assertion-accepted.xml';

    public const string RESPONSE_REQUEST_ID = '_request';

    public const string LOGOUT_REQUEST_ID = '_5d1a0e7c9b3f4a2e8d6c1b0a9f8e7d6c5b4a3f2e';

    public const string SSO = 'https://idp.example.com/saml/sso';

    public const string IDP_SLO = 'https://idp.example.com/saml/slo';

    public const string SP_SLO = 'https://sp.example.com/saml/slo';

    public const string ACS = 'https://sp.example.com/saml/acs';

    private static function receiver(): RedirectReceiver
    {
        return new RedirectReceiver(SamlLoader::create());
    }

    private static function postReceiver(): PostReceiver
    {
        return new PostReceiver(SamlLoader::create());
    }

    /**
     * Section 6.8
     *
     * @return array<array-key, mixed>
     */
    private static function form(string $field, string $message, ?string $relayState = null): array
    {
        return BrowserForm::posted(
            $relayState === null
                ? [[$field, base64_encode($message)]]
                : [
                    [$field,       base64_encode($message)],
                    ['RelayState', $relayState],
                ],
        );
    }

    private static function reception(RedirectQuery $query, Service $service): Reception
    {
        return Reception::ofQueryString($query->toString(), $service, SamlLoader::create(), 8_192, 65_536);
    }

    private static function formReception(string $field, string $message, Service $service): Reception
    {
        return Reception::ofForm(self::form($field, $message), $service, SamlLoader::create(), 1_572_864);
    }

    private static function serviceProvider(): ServiceProvider
    {
        return self::serviceProviderOf([TestKeys::certificate('sp')]);
    }

    /**
     * @param list<string> $certificates
     */
    private static function serviceProviderOf(array $certificates): ServiceProvider
    {
        return new ServiceProvider(
            'https://sp.example.com/saml',
            $certificates,
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::ACS, 0, true)]),
            [new Endpoint(Binding::HttpRedirect, self::SP_SLO)],
        );
    }

    private static function serviceProviderSigningItsRequests(): ServiceProvider
    {
        return new ServiceProvider(
            'https://sp.example.com/saml',
            [TestKeys::certificate('sp')],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::ACS, 0, true)]),
            [new Endpoint(Binding::HttpRedirect, self::SP_SLO)],
            [],
            true,
        );
    }

    private static function identityProvider(): IdentityProvider
    {
        return self::identityProviderOf([TestKeys::certificate('idp')]);
    }

    /**
     * @param list<string> $certificates
     */
    private static function identityProviderOf(array $certificates): IdentityProvider
    {
        return new IdentityProvider(
            'https://idp.example.com/saml',
            $certificates,
            [],
            [new Endpoint(Binding::HttpRedirect, self::SSO)],
            [new Endpoint(Binding::HttpRedirect, self::IDP_SLO)],
        );
    }

    private static function authnRequestValidator(): AuthnRequestValidator
    {
        return new AuthnRequestValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-10-01T12:00:00Z')),
        );
    }

    private static function logoutRequestValidator(): LogoutRequestValidator
    {
        return new LogoutRequestValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z')),
            new InMemoryReplayGuard(),
        );
    }

    private static function logoutResponseValidator(): LogoutResponseValidator
    {
        return new LogoutResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z')),
            new InMemoryReplayGuard(),
        );
    }

    private static function responseValidator(string $now = '2026-09-30T12:00:00Z'): ResponseValidator
    {
        return new ResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable($now)),
            new InMemoryReplayGuard(),
        );
    }

    private static function expectedResponse(string $requestId = self::RESPONSE_REQUEST_ID): ExpectedResponse
    {
        return ExpectedResponse::toRequest($requestId, self::ACS, 'https://sp.example.com/saml');
    }
}
