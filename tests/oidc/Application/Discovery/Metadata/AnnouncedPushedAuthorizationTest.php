<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedPushedAuthorization;
use Beffroi\Oidc\Port\PushedAuthorizationRequirementInterface;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\PushedRequests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9126 §5
 */
final class AnnouncedPushedAuthorizationTest extends TestCase
{
    #[Test]
    public function itNamesTheEndpointOfTheTenant(): void
    {
        // Given
        $announced = new AnnouncedPushedAuthorization(new Endpoints(), PushedRequests::requiredOfNobody());

        // When
        $members = $announced->metadata(Fixtures::tenant('acme', 'https://as.example/acme'));

        // Then
        static::assertSame('https://as.example/acme/par', $members['pushed_authorization_request_endpoint']);
    }

    #[Test]
    #[DataProvider('provideRequirements')]
    public function itSaysWhetherTheTenantTakesARequestAnyOtherWay(PushedAuthorizationRequirementInterface $requirement, bool $required): void
    {
        // Given
        $announced = new AnnouncedPushedAuthorization(new Endpoints(), $requirement);

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame($required, $members['require_pushed_authorization_requests']);
    }

    /**
     * @return iterable<string, array{PushedAuthorizationRequirementInterface, bool}>
     */
    public static function provideRequirements(): iterable
    {
        yield 'a tenant whose clients all push' => [PushedRequests::requiredOfEveryClient(), true];
        yield 'a tenant that takes a request either way' => [PushedRequests::requiredOfNobody(), false];
    }
}
