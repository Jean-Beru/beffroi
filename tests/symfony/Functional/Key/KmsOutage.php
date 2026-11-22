<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Key;

use LogicException;
use SensitiveParameter;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\KeyManagement\DataKeyGeneratorInterface;
use Symfony\Component\KeyManagement\Envelope;
use Symfony\Component\KeyManagement\EnvelopeDecrypterInterface;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;
use Symfony\Component\KeyManagement\EnvelopeEncrypterInterface;
use Symfony\Component\KeyManagement\Exception\RuntimeException;

final class KmsOutage implements EnvelopeEncrypterInterface, EnvelopeDecrypterInterface
{
    public const string WORDS_OF_THE_KMS = 'Failed to reach the KMS.';

    public bool $down = false;

    private ?EnvelopeEncrypter $envelopes = null;

    public function takeOver(ContainerInterface $container): void
    {
        $kms = $container->get('test.beffroi.kms');
        if (! $kms instanceof DataKeyGeneratorInterface) {
            throw new LogicException('The KMS of the kernel generates no data key.');
        }
        $this->envelopes = new EnvelopeEncrypter($kms);
        $container->set('beffroi.kms.envelopes', $this);
    }

    public function encrypt(string $key, #[SensitiveParameter] string $plaintext, string $aad = ''): Envelope
    {
        return $this->reach()->encrypt($key, $plaintext, $aad);
    }

    public function decrypt(Envelope $envelope, string $aad = ''): string
    {
        return $this->reach()->decrypt($envelope, $aad);
    }

    private function reach(): EnvelopeEncrypter
    {
        if ($this->down) {
            throw new RuntimeException(self::WORDS_OF_THE_KMS);
        }

        return $this->envelopes ?? throw new LogicException('The KMS of no kernel was taken over.');
    }
}
