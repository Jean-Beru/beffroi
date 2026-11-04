<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Tests\Symfony\Fixture\DoctrineDeprecations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

final class ThePagesOfTheAccountRaiseNoDeprecationTest extends BrowserTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->signIn(self::user('alice'));
    }

    #[Test]
    #[DataProvider('provideThePagesOfTheAccount')]
    public function aPageOfTheAccountRaisesNoDeprecationOfDoctrine(string $page): void
    {
        // When
        $deprecations = DoctrineDeprecations::raisedWhile(fn (): object => $this->browser->request('GET', $page));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame([], $deprecations);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideThePagesOfTheAccount(): iterable
    {
        yield 'the home of the account' => ['/account'];
        yield 'the acts' => ['/account/acts'];
        yield 'the requests waiting' => ['/account/approvals'];
        yield 'the archive' => ['/account/archive'];
        yield 'the consents' => ['/account/consents'];
        yield 'the notifications' => ['/account/notifications'];
        yield 'the passkeys' => ['/account/passkeys'];
        yield 'the password' => ['/account/password'];
        yield 'the profile' => ['/account/profile'];
        yield 'the changes of the profile' => ['/account/profile/changes'];
        yield 'the sessions' => ['/account/sessions'];
        yield 'the two-factor authentication' => ['/account/two-factor'];
    }
}
