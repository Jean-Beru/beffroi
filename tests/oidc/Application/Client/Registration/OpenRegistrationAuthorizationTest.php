<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Registration;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Heidi\Oidc\Domain\Client\Registration\RegistrationRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §1.3, decision 0009: the mode built second. A registration is authorised by nothing at all,
 * which is what the `dynamic_client` variant of the conformance suite sends.
 */
final class OpenRegistrationAuthorizationTest extends TestCase
{
    /**
     * A mode that registers whoever asks has nothing to compare and nothing to spend: a credential
     * presented to it is read by nothing, and it puts nothing in front of the members the client sent.
     */
    #[Test]
    #[DataProvider('providePresentedCredentials')]
    public function aRequestIsAuthorisedWhateverItPresentsAndNothingIsAddedToIt(?string $header): void
    {
        // Given
        $authorization = new OpenRegistrationAuthorization();

        // When
        $sources = $authorization->authorize(Fixtures::tenant(), new RegistrationRequest([], $header));

        // Then
        static::assertSame([], $sources);
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function providePresentedCredentials(): iterable
    {
        yield 'no Authorization header at all' => [null];

        yield 'a bearer credential of the controlled mode' => ['Bearer a-value-a-tenant-handed-out'];

        yield 'a credential of a shape this provider never draws' => ['Basic Zm9vOmJhcg=='];
    }
}
