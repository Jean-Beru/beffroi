<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\PostForm;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, section 6.7, SAML Bindings §3.5.4
 */
final class PostFormTest extends TestCase
{
    /**
     * Section 6.7, SAML Bindings §3.5.4
     */
    #[Test]
    public function itHoldsItsActionAndFieldsAsGiven(): void
    {
        // When
        $form = new PostForm(
            'https://sp.example.com/saml/acs?tenant=acme&lang=fr',
            ['SAMLResponse' => 'PHg+', 'RelayState' => '<b>"&\'</b>'],
        );

        // Then
        static::assertSame(
            [
                'https://sp.example.com/saml/acs?tenant=acme&lang=fr',
                ['SAMLResponse' => 'PHg+', 'RelayState' => '<b>"&\'</b>'],
            ],
            [$form->action, $form->fields],
        );
    }
}
