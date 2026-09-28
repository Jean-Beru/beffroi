<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Authorization\AuthorizationErrorResponse;
use Heidi\Oidc\Domain\Authorization\RedirectTarget;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientPresentation;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Exception\UnsupportedResponseTypeException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Heidi\Oidc\Tests\Fixture\Shapes;

final class AuthorizationErrorResponseTest extends TestCase
{
    /**
     * RFC 6749 §4.1.2.1: error, error_description and state in the query component of the redirect URI;
     * RFC 9207 §2: iss in every authorization response, the error ones included.
     */
    #[Test]
    public function itRedirectsWithErrorStateAndIssuer(): void
    {
        // Given
        $target = new RedirectTarget(Clients::public(Fixtures::tenant()), new RedirectUri('https://spa.example/callback'), 'af0ifjsldkj');

        // When
        $response = AuthorizationErrorResponse::fromException($target, new UnsupportedResponseTypeException('Only the code response type is supported.'));

        // Then
        static::assertSame(
            [
                'error' => 'unsupported_response_type',
                'error_description' => 'Only the code response type is supported.',
                'state' => 'af0ifjsldkj',
                'iss' => 'https://id.acme.example',
            ],
            $response->parameters(),
        );
    }

    /**
     * RFC 6749 §4.1.2.1: state is present in the response only when it was in the request.
     */
    #[Test]
    public function itOmitsTheStateWhenTheRequestHadNone(): void
    {
        // Given
        $target = new RedirectTarget(Clients::public(Fixtures::tenant()), new RedirectUri('https://spa.example/callback'), null);

        // When
        $response = AuthorizationErrorResponse::fromException($target, new InvalidRequestException('The scope parameter is missing.', true));

        // Then
        static::assertArrayNotHasKey('state', $response->parameters());
    }

    /**
     * RFC 6749 §4.1.2.1: the state comes back as the client sent it, whatever it contains; what encodes
     * it is the mode that delivers the response (RedirectUri::withParameters for the default one).
     */
    #[Test]
    public function itCarriesTheStateAsTheClientSentIt(): void
    {
        // Given
        $client = new Client(
            Fixtures::tenant(),
            new ClientRegistration(
                'app',
                new ClientPresentation('Application'),
                Methods::none(),
                false,
                [new RedirectUri('https://rp.example/cb?app=1')],
                Shapes::jwt(),
            ),
        );
        $target = new RedirectTarget($client, new RedirectUri('https://rp.example/cb?app=1'), 'a state with spaces & ampersand');

        // When
        $parameters = AuthorizationErrorResponse::fromException($target, new InvalidRequestException('The scope parameter is missing.', true))->parameters();

        // Then
        static::assertSame('a state with spaces & ampersand', $parameters['state']);
    }

    /**
     * RFC 6749 §4.1.2.1 and RFC 9700 §4.1: an error raised before the client and its redirect URI were
     * validated is shown to the user; turning it into a redirect is a programming error.
     */
    #[Test]
    public function itRefusesToRedirectAnErrorThatMustBeShown(): void
    {
        // Given
        $target = new RedirectTarget(Clients::public(Fixtures::tenant()), new RedirectUri('https://spa.example/callback'), null);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('invalid_client');

        // When
        AuthorizationErrorResponse::fromException($target, new InvalidClientException('Unknown client.'));
    }
}
