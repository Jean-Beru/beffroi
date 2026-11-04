<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\SingleLogout;

use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * S-26
 */
final class SessionParticipationTest extends TestCase
{
    /**
     * S-26, decision 0011
     */
    #[Test]
    public function aRowNamesNoPerson(): void
    {
        // When / Then
        static::assertEquals(
            [
                'id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
                'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
                'session' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
                'serviceProvider' => new NoPersonalDatum('names a service provider, an application and never a person'),
                'signedInAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            ],
            SessionParticipation::classifiedFields(),
        );
    }
}
