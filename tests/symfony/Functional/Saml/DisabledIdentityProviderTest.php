<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Saml;

use App\Saml\JoseSamlSigningAlgorithms;
use App\Saml\SamlSigning;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;

/**
 * beffroi/saml, spec/saml.md section 5.1
 */
final class DisabledIdentityProviderTest extends ConsoleTestCase
{
    private const string WITHOUT_SAML = 'test_without_saml';

    private static ?GeneratedKeyPair $samlPair = null;

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::WITHOUT_SAML,
        ];
    }

    /**
     * Section 5.1, S-1
     */
    #[Test]
    public function theJwkSetIsServedWithTheOtherKeys(): void
    {
        // Given
        $signing = self::signingKey();
        self::samlKeyLeftBehind();

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame([$signing->kid], self::servedKids($response));
    }

    /**
     * Section 5.1
     */
    #[Test]
    public function aClientIsIssuedItsTokens(): void
    {
        // Given
        $signing = self::signingKey();
        self::samlKeyLeftBehind();
        $this->signIn(self::user());

        // When
        $this->signInClient('native-app', 'http://127.0.0.1/callback', null);

        // Then
        static::assertSame($signing->kid, self::kidOf(self::string(self::json($this->browser->getResponse())['id_token'] ?? null)));
    }

    /**
     * Section 5.1
     *
     * @param array<string, string|bool> $input
     */
    #[Test]
    #[DataProvider('provideKeyCommands')]
    public function theKeyCommandsGoOn(string $command, array $input): void
    {
        // Given
        self::signingKey();
        self::samlKeyLeftBehind();

        // When
        $tester = self::console($command, $input);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
    }

    /**
     * @return iterable<string, array{string, array<string, string|bool>}>
     */
    public static function provideKeyCommands(): iterable
    {
        yield 'the keys in service' => ['beffroi:keys:list', []];
        yield 'every key' => [
            'beffroi:keys:list',
            [
                '--all' => true,
            ],
        ];
        yield 'the check of the keys in use' => [
            'beffroi:keys:list',
            [
                '--check' => true,
            ],
        ];
        yield 'a rotation of the key that signs' => [
            'beffroi:keys:rotate',
            [
                '--algorithm' => 'RS256',
            ],
        ];
        yield 'the retirements that are due' => [
            'beffroi:keys:retire',
            [
                '--due' => true,
            ],
        ];
    }

    /**
     * Section 5.1, section 6.1 step 1
     */
    #[Test]
    public function theMetadataAnswersThatThereIsNone(): void
    {
        // Given
        self::samlKeyLeftBehind();

        // When
        $this->browser->request('GET', '/saml/metadata');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    private static function samlKeyLeftBehind(): void
    {
        $algorithm = new SamlSigning();
        $pair =
            self::$samlPair ??= new JwtLibraryKeyPairGenerator(Algorithms::readAsOne([
                new JoseSamlSigningAlgorithms([$algorithm]),
            ]))->generate($algorithm);
        $tenant = self::tenant();
        $now = Clock::get()->now();
        $key = new TenantKey(
            $pair->kid,
            $tenant,
            $algorithm,
            $pair->publicJwk,
            self::service('test.beffroi.key_sealer', KeySealerInterface::class)->seal($tenant, $pair->privateJwk),
            $now,
            $now,
        );
        $key->activate($now);
        self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)->save($key);
    }

    /**
     * @return list<string>
     */
    private static function servedKids(Response $response): array
    {
        $keys = self::json($response)['keys'] ?? null;
        static::assertIsArray($keys);
        $kids = [];
        foreach ($keys as $key) {
            static::assertIsArray($key);
            $kids[] = self::string($key['kid'] ?? null);
        }

        return $kids;
    }
}
