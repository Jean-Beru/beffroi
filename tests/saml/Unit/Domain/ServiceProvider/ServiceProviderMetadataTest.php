<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\ServiceProvider;

use ArgumentCountError;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md section 5.2, S-9, S-11: what a reading of the metadata of a service provider returns.
 */
final class ServiceProviderMetadataTest extends TestCase
{
    /**
     * S-9, S-11: whether the provider signs its requests and the keys that verify them are never defaulted, so that a
     * reading that leaves them out fails where it is written rather than reporting a provider that says nothing and
     * holds no key. PHPStan refuses the call below at level max, and the ignore it carries is itself refused once the
     * call is allowed again, PHPStan reporting an ignore that matches nothing.
     */
    #[Test]
    public function aReadingCannotLeaveOutWhatDecidesTheSignatureOfARequest(): void
    {
        // Then
        $this->expectException(ArgumentCountError::class);
        $this->expectExceptionMessageIsOrContains('3 passed');

        // When
        new ServiceProviderMetadata('https://sp.example.com/saml', null, []); // @phpstan-ignore arguments.count, new.resultUnused (the contract is broken on purpose)
    }
}
