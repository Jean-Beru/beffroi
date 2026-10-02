<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Ciba;

use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationResponse;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * CIBA Core §7.3: what the client is answered, and nothing else.
 */
final class BackchannelAuthenticationResponseTest extends TestCase
{
    /**
     * §7.3: the identifier, the lifetime and the interval, and no token anywhere (§10.3 is not served).
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

    /**
     * A lifetime already spent is no answer a client could use.
     */
    #[Test]
    public function itAnswersALifetimeOfAtLeastOneSecond(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request is answered with the seconds it still lives, at least one (CIBA Core section 7.3).');

        // When
        new BackchannelAuthenticationResponse('the-auth-req-id', 0, 5);
    }

    /**
     * An interval of no seconds is not an interval.
     */
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
