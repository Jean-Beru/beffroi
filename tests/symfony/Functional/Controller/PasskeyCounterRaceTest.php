<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Doctrine\EntityManagers;
use App\Doctrine\Repository\ConditionalCredentialWrite;
use App\Doctrine\Repository\DoctrinePasskeyUses;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\PasskeyUsed;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\PasskeyUsesRacedByAnotherRequest;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use Closure;
use Doctrine\Persistence\ManagerRegistry;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * Architecture §5.4, WebAuthn Level 3 §6.1.1, Decision 0034
 */
final class PasskeyCounterRaceTest extends PasskeyTestCase
{
    private ?PasskeyUsesRacedByAnotherRequest $uses = null;

    private SoftwareAuthenticator $device;

    private User $alice;

    protected function setUp(): void
    {
        parent::setUp();
        $this->device = self::device();
        $this->alice = self::user('alice');
    }

    protected function configureContainer(): Closure
    {
        return function (ContainerInterface $container): void {
            $registry = $container->get('doctrine');
            static::assertInstanceOf(ManagerRegistry::class, $registry);
            $this->uses = new PasskeyUsesRacedByAnotherRequest(new DoctrinePasskeyUses(new ConditionalCredentialWrite(new EntityManagers($registry))));
            $container->set(DoctrinePasskeyUses::class, $this->uses);
        };
    }

    #[Test]
    public function aLoginWhoseCounterAnotherLoginWroteMeanwhileIsRefused(): void
    {
        // Given
        $interaction = $this->aLoginRacedByAnotherCarryingTheSameCounter();

        // When
        $this->loginWithPasskey($interaction, $this->device);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertFalse($this->isBoundToASession());
    }

    #[Test]
    public function theRefusalIsAnnouncedWithItsPersonAndNoUse(): void
    {
        // Given
        $interaction = $this->aLoginRacedByAnotherCarryingTheSameCounter();

        // When
        $this->loginWithPasskey($interaction, $this->device);

        // Then
        $failures = self::events(AuthenticationFailed::class);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $failures[0]->reason);
        static::assertSame('hwk', $failures[0]->method?->value);
        static::assertTrue($failures[0]->user?->id->equals($this->alice->id));
        static::assertSame([], self::events(PasskeyUsed::class));
    }

    private function aLoginRacedByAnotherCarryingTheSameCounter(): string
    {
        $passkey = $this->enrol($this->alice, $this->device);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();
        self::forgetEvents();
        $uses = $this->uses ?? static::fail('The uses of a passkey were not taken over.');
        $uses->anotherRequest = static function () use ($passkey): void {
            self::entityManager()
                ->getConnection()
                ->executeStatement(
                    'UPDATE beffroi_passkey_credential SET sign_count = sign_count + 1 WHERE id = :id',
                    [
                        'id' => $passkey->id,
                    ],
                    [
                        'id' => UuidType::NAME,
                    ],
                );
        };

        return $interaction;
    }
}
