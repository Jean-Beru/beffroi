<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Session;

use Beffroi\Core\Application\Session\ProvedMethods;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8176 §2
 */
final class ProvedMethodsTest extends TestCase
{
    #[Test]
    public function everyMethodTheOpenSessionsOfThePersonProvedIsNamedOnceInTheOrderOfTheirNames(): void
    {
        // Given
        $alice = Fixtures::user();
        $sessions = new InMemoryAuthenticationSessionRepository();
        $sessions->save(Fixtures::session($alice));
        $sessions->save(Fixtures::session($alice, proofs: AuthenticationProofs::of(
            new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY),
            Fixtures::now(),
        )));
        $sessions->save(Fixtures::session($alice));
        $sessions->save(Fixtures::session(
            Fixtures::user(username: 'bob', subject: 'bob-subject'),
            proofs: AuthenticationProofs::of(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::now()),
        ));
        $ended = Fixtures::session($alice, proofs: AuthenticationProofs::of(new AuthenticationMethod(AuthenticationMethod::SOFTWARE_KEY), Fixtures::now()));
        $ended->end(SessionEnd::User, Fixtures::now());
        $sessions->save($ended);

        // When
        $methods = new ProvedMethods($sessions)->of($alice, Fixtures::now()->modify('+1 hour'));

        // Then
        static::assertSame([AuthenticationMethod::HARDWARE_KEY, AuthenticationMethod::PASSWORD], $methods);
    }
}
