<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\AuthenticatorModel;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The make and model of an authenticator as a source names them: a name, and the source that gave it.
 */
final class AuthenticatorModelTest extends TestCase
{
    #[Test]
    public function aModelWithoutANameIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A model of authenticator has a name.');

        // When
        new AuthenticatorModel('', 'fido-metadata-service');
    }

    #[Test]
    public function aModelNamedByASourceWithoutANameIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A model of authenticator is named by a source that has a name.');

        // When
        new AuthenticatorModel('YubiKey 5 Series', '');
    }
}
