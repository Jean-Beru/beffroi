<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery;

use Heidi\Oidc\Application\Discovery\ServedGrantTypes;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\FakeGrant;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The grants the token endpoint serves are named by the grants themselves, so the document cannot
 * announce one the endpoint would refuse (issue #98).
 */
final class ServedGrantTypesTest extends TestCase
{
    #[Test]
    public function theyAreTheGrantsTheTokenEndpointIsWiredWith(): void
    {
        // When
        $served = new ServedGrantTypes([new FakeGrant(GrantType::AuthorizationCode), new FakeGrant(GrantType::RefreshToken)]);

        // Then
        static::assertSame([GrantType::AuthorizationCode, GrantType::RefreshToken], $served->all);
    }

    #[Test]
    public function aTokenEndpointWithoutAGrantIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The token endpoint serves at least one grant.');

        // When
        new ServedGrantTypes([]);
    }
}
