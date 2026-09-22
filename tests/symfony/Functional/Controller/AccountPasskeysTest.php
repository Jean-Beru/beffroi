<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Domain\Event\CredentialEnrolled;
use Heidi\Core\Domain\Event\CredentialRevoked;
use Heidi\Core\Port\CredentialRepositoryInterface;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use function ksort;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function str_repeat;
use function strlen;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of the passkeys of the signed-in user (architecture §5.2): the list, the enrolment through the
 * ceremony of the core, the revocation, the script of the bundle. The authenticator of the browser is a
 * software one.
 */
final class AccountPasskeysTest extends PasskeyTestCase
{
    #[Test]
    public function thePageNeedsASessionOfTheCore(): void
    {
        // When
        $crawler = $this->browser->request('GET', '/account/passkeys');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertSame('login_required', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function thePageListsNothingForAUserWithoutAPasskey(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->passkeysPage();

        // Then
        self::assertInteractionHeaders($this->browser->getResponse());
        static::assertCount(1, $crawler->filter('p[data-passkeys="none"]'));
        static::assertCount(0, $crawler->filter('table'));
        static::assertSame('/passkey.js', $crawler->filter('script')->attr('src'));
        $form = $crawler->filter('form[data-passkey="enrol"]');
        static::assertSame('/account/passkeys', $form->attr('action'));
        static::assertSame('/account/passkeys/options', $form->attr('data-options-url'));
        static::assertNotNull($form->attr('hidden'), 'The form waits for the script to find a capable browser.');
        static::assertCount(1, $form->filter('input[name="name"]'));
    }

    /**
     * WebAuthn Level 3 §5.4: the options of a discoverable credential for this user, no attestation asked.
     */
    #[Test]
    public function theCreationOptionsAreForThisUserAndThisTenant(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('POST', '/account/passkeys/options');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        self::assertInteractionHeaders($response);
        $options = json_decode(self::string($response->getContent()), true, 8, JSON_THROW_ON_ERROR);
        static::assertIsArray($options);
        static::assertSame(
            [
                'id' => 'op.test',
                'name' => 'op.test',
            ],
            self::sorted($options['rp']),
        );
        $user = self::sorted($options['user']);
        static::assertSame('alice', $user['name']);
        static::assertSame(86, strlen(self::string($user['id'])), 'A 64-byte handle in base64url.');
        static::assertSame(
            [
                'requireResidentKey' => true,
                'residentKey' => 'required',
                'userVerification' => 'preferred',
            ],
            self::sorted($options['authenticatorSelection']),
        );
        static::assertSame('none', $options['attestation']);
        static::assertSame([], $options['excludeCredentials']);
    }

    #[Test]
    public function theCreationOptionsNeedASessionOfTheCore(): void
    {
        // When
        $this->browser->request('POST', '/account/passkeys/options');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame(
            [
                'error' => 'login_required',
            ],
            self::json($response),
        );
    }

    /**
     * The second criterion of the acceptance on this side: a passkey enrolled from a logged-in session,
     * named, listed.
     */
    #[Test]
    public function aPasskeyIsEnrolledFromTheSessionAndListed(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $this->signIn($alice);
        $token = $this->passkeysPage()->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');
        $options = $this->creationOptions();

        // When
        $this->browser->request('POST', '/account/passkeys', [
            '_token' => $token,
            'name' => 'YubiKey 5',
            '_passkey' => $device->create($options),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/account/passkeys', $response->headers->get('Location'));
        $enrolled = self::events(CredentialEnrolled::class);
        static::assertCount(1, $enrolled);
        static::assertSame('127.0.0.1', $enrolled[0]->context->ipAddress);
        $passkey = self::passkeyOf($alice, $device);
        static::assertSame('YubiKey 5', $passkey->name);
        static::assertTrue($passkey->user->id->equals($alice->id));
        $row = $this->passkeysPage()->filter('table[data-passkeys="1"] tr[data-passkey="' . $passkey->id . '"]');
        static::assertCount(1, $row);
        static::assertSame('no', $row->attr('data-revoked'));
        static::assertStringContainsString('YubiKey 5', $row->text());
    }

    /**
     * §5.4, excludeCredentials: a second passkey is drawn with the first one excluded and the same handle.
     */
    #[Test]
    public function aSecondPasskeyIsDrawnWithTheFirstExcluded(): void
    {
        // Given
        $alice = self::user('alice');
        $first = $this->enrol($alice, self::device(), 'First');

        // When
        $options = json_decode($this->creationOptions(), true, 8, JSON_THROW_ON_ERROR);

        // Then
        static::assertIsArray($options);
        static::assertSame(
            [
                [
                    'type' => 'public-key',
                    'id' => Base64UrlSafe::encodeUnpadded($first->credentialId),
                    'transports' => ['usb'],
                ],
            ],
            $options['excludeCredentials'],
        );
        static::assertSame(Base64UrlSafe::encodeUnpadded($first->userHandle->value), self::sorted($options['user'])['id']);
    }

    /**
     * @param callable(self, string): Crawler $post
     */
    #[Test]
    #[DataProvider('provideRefusedEnrolments')]
    public function anEnrolmentThatDoesNotHoldIsRefusedWithItsReason(callable $post, string $error): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $token = $this->passkeysPage()->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');
        static::assertIsString($token);

        // When
        $crawler = $post($this, $token);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNPROCESSABLE_ENTITY, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame($error, $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame([], self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findByUser($alice, PasskeyCredential::class));
        static::assertSame([], self::events(CredentialEnrolled::class));
    }

    /**
     * @return iterable<string, array{callable(self, string): Crawler, string}>
     */
    public static function provideRefusedEnrolments(): iterable
    {
        yield 'no name' => [
            static fn (self $test, string $token) => $test->browser->request('POST', '/account/passkeys', [
                '_token' => $token,
                'name' => '   ',
                '_passkey' => self::device()->create($test->creationOptions()),
            ]),
            'invalid_name',
        ];
        yield 'a name too long' => [
            static fn (self $test, string $token) => $test->browser->request('POST', '/account/passkeys', [
                '_token' => $token,
                'name' => str_repeat('k', 256),
                '_passkey' => self::device()->create($test->creationOptions()),
            ]),
            'invalid_name',
        ];
        yield 'no ceremony pending' => [
            static fn (self $test, string $token) => $test->browser->request('POST', '/account/passkeys', [
                '_token' => $token,
                'name' => 'Key',
                '_passkey' => self::device()
                    ->create('{"rp":{"id":"op.test"},"user":{"id":"' . str_repeat('A', 86) . '"},"challenge":"' . str_repeat('A', 43) . '"}'),
            ]),
            'no_ceremony',
        ];
        yield 'no attestation' => [
            static function (self $test, string $token): Crawler {
                $test->creationOptions();

                return $test->browser->request('POST', '/account/passkeys', [
                    '_token' => $token,
                    'name' => 'Key',
                    '_passkey' => '',
                ]);
            },
            'no_ceremony',
        ];
        yield 'an attestation from another origin' => [
            static fn (self $test, string $token) => $test->browser->request('POST', '/account/passkeys', [
                '_token' => $token,
                'name' => 'Key',
                '_passkey' => self::device()->atOrigin('https://phishing.example')->create($test->creationOptions()),
            ]),
            'refused',
        ];
        yield 'an attestation for another relying party' => [
            static fn (self $test, string $token) => $test->browser->request('POST', '/account/passkeys', [
                '_token' => $token,
                'name' => 'Key',
                '_passkey' => self::device()->forRelyingParty('other.test')->create($test->creationOptions()),
            ]),
            'refused',
        ];
        yield 'an attestation of another challenge' => [
            static function (self $test, string $token): Crawler {
                $stale = $test->creationOptions();
                $test->creationOptions();

                return $test->browser->request('POST', '/account/passkeys', [
                    '_token' => $token,
                    'name' => 'Key',
                    '_passkey' => self::device()->create($stale),
                ]);
            },
            'refused',
        ];
    }

    /**
     * WebAuthn Level 3 §7.1, step 26: a credential ID the tenant knows is refused.
     */
    #[Test]
    public function aPasskeyEnrolledTwiceIsRefusedTheSecondTime(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $this->enrol($alice, $device);
        $token = $this->passkeysPage()->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');

        // When
        $crawler = $this->browser->request('POST', '/account/passkeys', [
            '_token' => $token,
            'name' => 'Again',
            '_passkey' => $device->create($this->creationOptions()),
        ]);

        // Then
        static::assertSame(Response::HTTP_UNPROCESSABLE_ENTITY, $this->browser->getResponse()->getStatusCode());
        static::assertSame('refused', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertCount(1, self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findByUser($alice, PasskeyCredential::class));
    }

    #[Test]
    public function anEnrolmentWithoutItsTokenIsRefused(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $options = $this->creationOptions();

        // When
        $crawler = $this->browser->request('POST', '/account/passkeys', [
            '_token' => 'not-the-token',
            'name' => 'Key',
            '_passkey' => self::device()->create($options),
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertSame('invalid_csrf_token', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame([], self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findByUser($alice, PasskeyCredential::class));
    }

    /**
     * The options are drawn for the user of the session that asked them: another user on the same browser
     * cannot complete with them.
     */
    #[Test]
    public function theOptionsOfAnotherUserAreNotUsed(): void
    {
        // Given
        $alice = self::user('alice');
        $bob = self::user('bob', 'bob-subject');
        $this->signIn($alice);
        $options = $this->creationOptions();
        $this->signIn($bob);
        $token = $this->passkeysPage()->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');

        // When
        $crawler = $this->browser->request('POST', '/account/passkeys', [
            '_token' => $token,
            'name' => 'Key',
            '_passkey' => self::device()->create($options),
        ]);

        // Then
        static::assertSame(Response::HTTP_UNPROCESSABLE_ENTITY, $this->browser->getResponse()->getStatusCode());
        static::assertSame('no_ceremony', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame([], self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findByUser($bob, PasskeyCredential::class));
    }

    #[Test]
    public function aPasskeyIsRevokedFromThePage(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $form = $this->passkeysPage()
            ->filter('tr[data-passkey="' . $passkey->id . '"]')
            ->selectButton('Revoke')
            ->form();

        // When
        $this->browser->submit($form);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/account/passkeys', $response->headers->get('Location'));
        $revoked = self::events(CredentialRevoked::class);
        static::assertCount(1, $revoked);
        static::assertTrue(self::passkeyOf($alice, $device)->isRevoked());
        $row = $this->passkeysPage()->filter('tr[data-passkey="' . $passkey->id . '"]');
        static::assertSame('yes', $row->attr('data-revoked'));
        static::assertCount(0, $row->filter('button'), 'No revoking twice.');
    }

    #[Test]
    public function aRevokedPasskeyNoLongerSignsIn(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $this->browser->submit(
            $this->passkeysPage()
                ->filter('tr[data-passkey="' . $passkey->id . '"]')
                ->selectButton('Revoke')
                ->form(),
        );
        $this->forgetTheBrowser();
        $interaction = $this->authorize();

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        static::assertFalse($this->isBoundToASession());
    }

    #[Test]
    public function somebodyElsesPasskeyIsNotFoundToRevoke(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $this->forgetTheBrowser();
        $bob = self::user('bob', 'bob-subject');
        $own = $this->enrol($bob, self::device());
        $token = $this->passkeysPage()
            ->filter('tr[data-passkey="' . $own->id . '"] input[name="_token"]')
            ->attr('value');

        // When
        $this->browser->request('POST', '/account/passkeys/' . $passkey->id . '/revoke', [
            '_token' => $token,
        ]);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertFalse(self::passkeyOf($alice, $device)->isRevoked());
    }

    #[Test]
    public function aRevocationWithoutItsTokenIsRefused(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);

        // When
        $crawler = $this->browser->request('POST', '/account/passkeys/' . $passkey->id . '/revoke', [
            '_token' => 'not-the-token',
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertSame('invalid_csrf_token', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertFalse(self::passkeyOf($alice, $device)->isRevoked());
    }

    #[Test]
    public function aRevocationNeedsASessionOfTheCore(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $this->forgetTheBrowser();

        // When
        $this->browser->request('POST', '/account/passkeys/' . $passkey->id . '/revoke', [
            '_token' => 'whatever',
        ]);

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
        static::assertFalse(self::passkeyOf($alice, $device)->isRevoked());
    }

    #[Test]
    public function thePageSpeaksTheLanguageOfTheBrowser(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->browser->request('GET', '/account/passkeys', server: [
            'HTTP_ACCEPT_LANGUAGE' => 'fr-FR,fr;q=0.9',
        ]);

        // Then
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Vos passkeys', $crawler->filter('h1')->text());
    }

    /**
     * Architecture §5.2: the one script of the bundle, served by the bundle, cacheable.
     */
    #[Test]
    public function theScriptIsServedByTheBundle(): void
    {
        // When
        $this->browser->request('GET', '/passkey.js');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('text/javascript; charset=utf-8', $response->headers->get('Content-Type'));
        static::assertTrue($response->headers->hasCacheControlDirective('public'));
        static::assertSame('3600', $response->headers->getCacheControlDirective('max-age'));
        static::assertNotNull($response->headers->get('ETag'));
        $script = $this->browser->getInternalResponse()->getContent();
        static::assertStringContainsString('navigator.credentials.get(', $script);
        static::assertStringContainsString('navigator.credentials.create(', $script);
    }

    /**
     * A JSON object as an array, keys sorted: the order the serializer writes is not the point.
     *
     * @return array<string, mixed>
     */
    private static function sorted(mixed $object): array
    {
        static::assertIsArray($object);
        $sorted = [];
        foreach ($object as $key => $value) {
            $sorted[(string) $key] = $value;
        }
        ksort($sorted);

        return $sorted;
    }

    #[Test]
    public function theScriptIsNotSentAgainToABrowserThatHasIt(): void
    {
        // Given
        $this->browser->request('GET', '/passkey.js');
        $etag = $this->browser->getResponse()->headers->get('ETag');

        // When
        $this->browser->request('GET', '/passkey.js', server: [
            'HTTP_IF_NONE_MATCH' => $etag,
        ]);

        // Then
        static::assertSame(Response::HTTP_NOT_MODIFIED, $this->browser->getResponse()->getStatusCode());
    }
}
