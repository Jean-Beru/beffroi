<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Confirmation\IssuedAddressConfirmation;
use Beffroi\Core\Port\AddressConfirmationSenderInterface;
use Beffroi\Core\Exception\LogicException;

final class RecordingAddressConfirmationSender implements AddressConfirmationSenderInterface
{
    /**
     * @var list<IssuedAddressConfirmation>
     */
    public private(set) array $sent = [];

    public function send(IssuedAddressConfirmation $issued): void
    {
        $this->sent[] = $issued;
    }

    public function last(): IssuedAddressConfirmation
    {
        return $this->sent[array_key_last($this->sent) ?? throw new LogicException('Nothing was sent.')];
    }
}
