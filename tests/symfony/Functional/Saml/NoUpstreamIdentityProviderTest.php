<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Saml;

use App\Command\SamlIdentityProviderListCommand;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;

/**
 * beffroi/saml, spec/saml.md section 5.7, S-41
 */
final class NoUpstreamIdentityProviderTest extends ConsoleTestCase
{
    /**
     * Section 5.7
     */
    #[Test]
    public function theListCommandAnswersATenantThatDeclaresNoIdentityProviderAsInvalid(): void
    {
        // When
        $tester = self::console(SamlIdentityProviderListCommand::NAME);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            'The tenant declares no identity provider: declare one under "beffroi.saml.identity_providers".',
            self::flattened($tester),
        );
    }
}
