<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\Registration\AuthorizedRegistration;
use Beffroi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Beffroi\Oidc\Tests\Fixture\Policies;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §1.3, Decision 0009
 */
final class OpenRegistrationAuthorizationTest extends TestCase
{
    #[Test]
    #[DataProvider('providePresentedCredentials')]
    public function aRequestIsAuthorisedWhateverItPresentsAndNothingIsAddedToIt(?string $header): void
    {
        // Given
        $authorization = new OpenRegistrationAuthorization();

        // When
        $authorized = $authorization->authorize(Fixtures::tenant(), new RegistrationRequest([], $header), Policies::open());

        // Then
        static::assertEquals(new AuthorizedRegistration(), $authorized);
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
