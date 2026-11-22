<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Ciba;

use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationResponse;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * CIBA Core §7.3
 */
final class BackchannelAuthenticationResponseTest extends TestCase
{
    /**
     * CIBA Core §7.3
     */
    #[Test]
    public function itAnswersTheIdentifierTheLifetimeAndTheInterval(): void
    {
        // When
        $parameters = new BackchannelAuthenticationResponse('the-auth-req-id', 300, 5)->parameters();

        // Then
        static::assertSame(
            [
                'auth_req_id' => 'the-auth-req-id',
                'expires_in' => 300,
                'interval' => 5,
            ],
            $parameters,
        );
    }

    #[Test]
    public function itAnswersALifetimeOfAtLeastOneSecond(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request is answered with the seconds it still lives, at least one (CIBA Core section 7.3).');

        // When
        new BackchannelAuthenticationResponse('the-auth-req-id', 0, 5);
    }

    #[Test]
    public function itAnswersAnIntervalOfAtLeastOneSecond(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request is answered with a polling interval of at least one second (CIBA Core section 7.3).');

        // When
        new BackchannelAuthenticationResponse('the-auth-req-id', 300, 0);
    }
}
