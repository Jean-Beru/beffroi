<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\SingleLogout;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Domain\SingleLogout\LogoutChain;
use Beffroi\Saml\Domain\SingleLogout\LogoutProgress;
use Beffroi\Saml\Domain\SingleLogout\SignOutNotice;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-31, S-32, section 7: a chain open ten minutes from its last step and kept under the digest of its
 * reference; a request of the provider valid five minutes.
 */
final class LogoutChainTest extends TestCase
{
    /**
     * S-32, section 7: a chain written now closes ten minutes later, open until the second before.
     */
    #[Test]
    public function aChainIsOpenTenMinutes(): void
    {
        // Given
        $chain = new LogoutChain(
            'digest',
            Fixtures::tenant(),
            null,
            new LogoutProgress([], [], null, false, null, null),
            LogoutChain::closesAt(Fixtures::now()),
        );

        // When / Then
        static::assertSame(
            [true, false],
            [$chain->isOpen(Fixtures::now()->modify('+599 seconds')), $chain->isOpen(Fixtures::now()->modify('+600 seconds'))],
        );
    }

    /**
     * S-32: what is kept of a reference is its SHA-256, in hexadecimal.
     */
    #[Test]
    public function aReferenceIsKeptAsItsDigest(): void
    {
        // When / Then
        static::assertSame('52367a6622b19f08825e915fad80c542ad4f4c34dbcebad9f5007994b3e39208', LogoutChain::digestOf('reference'));
    }

    /**
     * S-31, section 7: the request the provider sends is valid five minutes from its IssueInstant.
     */
    #[Test]
    public function aNoticeIsValidFiveMinutes(): void
    {
        // When / Then
        static::assertEquals(
            Fixtures::now()->modify('+300 seconds'),
            new SignOutNotice('https://id.acme.example/saml/metadata', 'https://sp.example.org/saml', 'nameid', 'session', Fixtures::now())->notOnOrAfter(),
        );
    }
}
