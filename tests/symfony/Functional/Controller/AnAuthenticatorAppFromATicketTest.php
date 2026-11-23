<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Http\TotpProvisioningStore;
use Beffroi\Core\Application\Ticket\TotpTicketIssue;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Ticket\IssuedTicket;
use Beffroi\Core\Domain\Ticket\TotpTicket;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Port\TotpTicketRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use function array_map;
use DateTimeImmutable;
use function intdiv;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\Attributes\Test;
use function str_replace;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0026
 */
final class AnAuthenticatorAppFromATicketTest extends BrowserTestCase
{
    private User $alice;

    protected function setUp(): void
    {
        parent::setUp();
        $this->alice = self::userWithPassword('alice', 'nine quiet lanterns drift over the harbour');
        self::reload();
    }

    #[Test]
    public function theLinkOpensAPageThatNamesTheAccountAndShowsTheSecretOfAnApp(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $page = $this->ticketPage($issued);

        // Then
        static::assertStringContainsString('alice', self::string($page->filter('p')->first()->text()));
        static::assertSame(
            [1, 1, 1],
            [
                $page->filter('figure[data-two-factor="qr-code"] svg')->count(),
                $page->filter('code[data-two-factor="key"]')->count(),
                $page->filter('form[data-two-factor="enrol"]')->count(),
            ],
        );
    }

    #[Test]
    public function theSecretStaysTheSameWhenThePageIsReadAgain(): void
    {
        // Given
        $issued = $this->issue();
        $first = self::keyOf($this->ticketPage($issued));

        // When
        $again = self::keyOf($this->ticketPage($issued));

        // Then
        static::assertSame($first, $again);
    }

    #[Test]
    public function theCodeThatHoldsEnrolsTheAppAndShowsItsBackupCodesOnce(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $page = $this->enrol($issued);

        // Then
        static::assertSame(
            [Response::HTTP_OK, TotpCredential::BACKUP_CODES, [false]],
            [
                $this->browser->getResponse()->getStatusCode(),
                $page->filter('ol[data-two-factor="backup-codes"] li')->count(),
                array_map(static fn (TotpCredential $totp): bool => $totp->isRevoked(), $this->totpsOfAlice()),
            ],
        );
    }

    #[Test]
    public function thePageOfTheBackupCodesCarriesTheButtonThatCopiesThem(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $page = $this->enrol($issued);

        // Then
        static::assertCount(1, $page->filter('main button[data-copy="backup-codes"]'));
    }

    #[Test]
    public function theSecretIsForgottenOnceTheAppIsEnrolled(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $this->enrol($issued);

        // Then
        static::assertFalse($this->readHttpSession()->has(TotpProvisioningStore::KEY));
    }

    #[Test]
    public function theAppHeldIsRevokedOnceTheNewOneIsEnrolled(): void
    {
        // Given
        $this->enrol($this->issue());

        // When
        $this->enrol($this->issue());

        // Then
        static::assertSame(
            [true, false],
            array_map(static fn (TotpCredential $totp): bool => $totp->isRevoked(), $this->totpsOfAlice()),
        );
    }

    #[Test]
    public function everySessionOfThePersonEndsWithTheSecretItOpenedWith(): void
    {
        // Given
        $session = $this->signIn($this->alice);
        $issued = $this->issue();

        // When
        $this->enrol($issued);

        // Then
        self::reload();
        $again = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
            ->find($session->id) ?? static::fail('The session is gone.');
        static::assertSame(SessionEnd::User, $again->endedBy);
    }

    #[Test]
    public function aTicketSpentOpensNothingAnyMore(): void
    {
        // Given
        $issued = $this->issue();
        $this->enrol($issued);

        // When
        $this->browser->request('GET', $this->path($issued));

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aLinkThatOpensNothingSaysOneFlatSentence(): void
    {
        // When
        $page = $this->browser->request('GET', '/two-factor/' . Uuid::v7()->toRfc4122() . '/not-the-value-of-any-link');

        // Then
        static::assertSame(
            [Response::HTTP_NOT_FOUND, 'totp_ticket_refused'],
            [$this->browser->getResponse()->getStatusCode(), $page->filter('[data-error]')->attr('data-error')],
        );
    }

    #[Test]
    public function aCodeThatDoesNotMatchIsSaidAndTheTicketStillOpens(): void
    {
        // Given
        $issued = $this->issue();
        $secret = self::secretOf($this->ticketPage($issued));

        // When
        $this->postCode($issued, self::codeOf($secret, new DateTimeImmutable('-2 minutes')));

        // Then
        static::assertSame(['refused', false], [$this->afterTheForm()->filter('[data-error]')->attr('data-error'), $this->ticketOf($issued)->isSpent()]);
    }

    #[Test]
    public function aCodePostedOnceTheSecretIsForgottenIsSaidToBeLate(): void
    {
        // Given
        $issued = $this->issue();
        $secret = self::secretOf($this->ticketPage($issued));
        $this->httpSession(static function (SessionInterface $httpSession): void {
            $httpSession->remove(TotpProvisioningStore::KEY);
        });

        // When
        $this->postCode($issued, self::codeOf($secret, new DateTimeImmutable()));

        // Then
        static::assertSame('no_provisioning', $this->afterTheForm()->filter('[data-error]')->attr('data-error'));
    }

    #[Test]
    public function aFormWithoutItsTokenEnrolsNothing(): void
    {
        // Given
        $issued = $this->issue();
        $secret = self::secretOf($this->ticketPage($issued));

        // When
        $this->browser->request('POST', $this->path($issued), [
            'code' => self::codeOf($secret, new DateTimeImmutable()),
        ]);

        // Then
        static::assertSame([], $this->totpsOfAlice());
    }

    /**
     * Decision 0025: a floor raised once the ticket was issued admits no app the ticket would enrol.
     */
    #[Test]
    public function aTenantThatAdmitsNoAppShowsNoSecretOnThePageOfATicket(): void
    {
        // Given
        $issued = $this->issue();
        self::harden(new PhishingResistant());

        // When
        $page = $this->ticketPage($issued);

        // Then
        static::assertSame(['not_admitted', 0], [$page->filter('[data-error]')->attr('data-error'), $page->filter('[data-two-factor="key"]')->count()]);
    }

    /**
     * @return IssuedTicket<TotpTicket>
     */
    private function issue(): IssuedTicket
    {
        $alice = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($this->alice->id) ?? static::fail('The person is gone.');
        $issued = self::service('test.beffroi.totp_tickets', TotpTicketIssue::class)->issue($alice, self::context());
        self::forgetEvents();

        return $issued;
    }

    /**
     * @param IssuedTicket<TotpTicket> $issued
     */
    private function path(IssuedTicket $issued): string
    {
        return '/two-factor/' . $issued->ticket->id->toRfc4122() . '/' . $issued->value;
    }

    /**
     * @param IssuedTicket<TotpTicket> $issued
     */
    private function ticketPage(IssuedTicket $issued): Crawler
    {
        $crawler = $this->browser->request('GET', $this->path($issued));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    /**
     * @param IssuedTicket<TotpTicket> $issued
     */
    private function enrol(IssuedTicket $issued): Crawler
    {
        $secret = self::secretOf($this->ticketPage($issued));

        return $this->postCode($issued, self::codeOf($secret, new DateTimeImmutable()));
    }

    /**
     * @param IssuedTicket<TotpTicket> $issued
     */
    private function postCode(IssuedTicket $issued, string $code): Crawler
    {
        $token = $this->browser->getCrawler()->filter('form[data-two-factor="enrol"] input[name="_token"]')->attr('value');
        static::assertIsString($token);

        return $this->browser->request('POST', $this->path($issued), [
            '_token' => $token,
            'code' => $code,
        ]);
    }

    /**
     * @param IssuedTicket<TotpTicket> $issued
     */
    private function ticketOf(IssuedTicket $issued): TotpTicket
    {
        self::reload();

        return (
            self::service('test.beffroi.totp_ticket_store', TotpTicketRepositoryInterface::class)
                ->find($issued->ticket->id) ?? static::fail('The ticket is gone.')
        );
    }

    /**
     * @return list<TotpCredential> in the order they were enrolled
     */
    private function totpsOfAlice(): array
    {
        self::reload();
        $alice = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($this->alice->id) ?? static::fail('The person is gone.');

        return self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($alice, TotpCredential::class);
    }

    private static function keyOf(Crawler $crawler): string
    {
        return $crawler->filter('code[data-two-factor="key"]')->text();
    }

    private static function secretOf(Crawler $crawler): TotpSecret
    {
        return new TotpSecret(Base32::decodeUpper(str_replace(' ', '', self::keyOf($crawler))));
    }

    private static function codeOf(TotpSecret $secret, DateTimeImmutable $at): string
    {
        return self::service('test.beffroi.totp_algorithm', TotpAlgorithmInterface::class)
            ->codeAt($secret, intdiv($at->getTimestamp(), TotpCredential::PERIOD));
    }
}
