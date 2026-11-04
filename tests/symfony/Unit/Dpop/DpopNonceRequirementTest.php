<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Dpop;

use App\Dpop\DpopNonceRequirement;
use Beffroi\Oidc\Bridge\Null\NoDpopNonce;
use Beffroi\Oidc\Port\DpopNonceInterface;
use Beffroi\Oidc\Tests\Fixture\FakeDpopNonce;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9449 §8
 */
final class DpopNonceRequirementTest extends TestCase
{
    #[Test]
    public function aProviderThatRequiresANonceIsWiredWithTheNonceItIssues(): void
    {
        // Given
        $asked = new FakeDpopNonce('a-nonce-of-the-provider');

        // When
        $nonce = DpopNonceRequirement::chosen(true, static fn (): DpopNonceInterface => $asked, self::neverBuilt(...));

        // Then
        static::assertSame($asked, $nonce);
    }

    #[Test]
    public function aProviderThatRequiresNoneIsWiredWithoutOne(): void
    {
        // Given
        $notAsked = new NoDpopNonce();

        // When
        $nonce = DpopNonceRequirement::chosen(false, self::neverBuilt(...), static fn (): DpopNonceInterface => $notAsked);

        // Then
        static::assertSame($notAsked, $nonce);
    }

    private static function neverBuilt(): DpopNonceInterface
    {
        static::fail('The nonce the deployment did not choose is built.');
    }
}
