<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function array_column;
use function base64_encode;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Event\AuthorizationCodeIssued;
use Beffroi\Oidc\Domain\Event\ConsentGranted;
use Beffroi\Oidc\Domain\Event\IntrospectionAnswered;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Event\UserInfoAnswered;
use const JSON_THROW_ON_ERROR;
use function json_decode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\MessageBusInterface;

final class TheProtocolIsInTheJournalOfThePersonTest extends BrowserTestCase
{
    #[Test]
    public function theJournalOfAPersonHoldsWhatTheProtocolDidInTheirName(): void
    {
        // Given
        self::signingKey();
        $alice = self::user('alice');
        self::announce(new UserAuthenticated(self::session($alice, self::currentSecond())));
        $this->exchange($this->codeAllowedBy($alice));

        // When
        $journal = $this->journalOfTheArchive();

        // Then
        static::assertSame(
            [UserAuthenticated::NAME, ConsentGranted::NAME, AuthorizationCodeIssued::NAME, TokensIssued::NAME],
            array_column($journal, 'act'),
        );
    }

    #[Test]
    public function eachActOfTheProtocolNamesTheClientThatObtainedIt(): void
    {
        // Given
        self::signingKey();
        $this->exchange($this->codeAllowedBy(self::user('alice')));

        // When
        $journal = $this->journalOfTheArchive();

        // Then
        static::assertSame(['native-app', 'native-app', 'native-app'], array_column($journal, 'client'));
    }

    #[Test]
    public function theJournalOfAPersonHoldsEveryReadAnApplicationMadeOfThem(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $token = $this->tokensOfTheDemoClient();

        // When
        $this->readUserInfo($token);
        $this->introspect($token);
        $journal = $this->journalOfTheArchive();

        // Then
        static::assertSame(
            [AuthorizationCodeIssued::NAME, TokensIssued::NAME, UserInfoAnswered::NAME, IntrospectionAnswered::NAME],
            array_column($journal, 'act'),
        );
    }

    /**
     * RFC 7662 §2.2
     */
    #[Test]
    public function anIntrospectionThatDescribesNothingIsNoLineOfTheJournal(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->tokensOfTheDemoClient();

        // When
        $this->introspect('a-token-this-provider-never-issued');
        $journal = $this->journalOfTheArchive();

        // Then
        static::assertSame([AuthorizationCodeIssued::NAME, TokensIssued::NAME], array_column($journal, 'act'));
    }

    private function tokensOfTheDemoClient(): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => 'https://demo.test/login/check',
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: self::demoCredentials(),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return self::string(self::json($this->browser->getResponse())['access_token']);
    }

    private function readUserInfo(string $accessToken): void
    {
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
    }

    private function introspect(string $token): void
    {
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $token,
            ],
            server: self::demoCredentials(),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
    }

    /**
     * @return array<string, string>
     */
    private static function demoCredentials(): array
    {
        return [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function journalOfTheArchive(): array
    {
        $this->askForTheArchive();
        $this->browser->request('GET', '/account/archive/file');
        $document = json_decode(self::string($this->browser->getResponse()->getContent()), true, 512, JSON_THROW_ON_ERROR);
        static::assertIsArray($document);
        $journal = $document['journal'] ?? null;
        static::assertIsArray($journal);

        /** @var list<array<string, mixed>> $journal */
        return $journal;
    }

    private function askForTheArchive(): void
    {
        $page = $this->browser->request('GET', '/account/archive');
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
        $this->browser->request('POST', '/account/archive', [
            '_token' => self::string($page->filter('form[data-archive-ask] input[name="_token"]')->attr('value')),
        ]);
        $this->afterTheForm();
    }

    /**
     * OIDC Core §3.1.2
     */
    private function codeAllowedBy(User $user): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->signIn($user);
        $consent = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
        $this->browser->submit($consent->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }

    private function exchange(string $code): void
    {
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'http://127.0.0.1/callback',
            'client_id' => 'native-app',
            'code_verifier' => self::CODE_VERIFIER,
        ]);
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
    }

    private static function announce(DomainEventInterface $event): void
    {
        self::service('event.bus', MessageBusInterface::class)->dispatch($event);
        self::reload();
    }
}
