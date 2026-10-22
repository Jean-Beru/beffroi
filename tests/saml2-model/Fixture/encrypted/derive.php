<?php

declare(strict_types=1);

/*
 * The encrypted responses of spec/model.md section 6.7, in two runs around xmlsec1 (README.md of this directory). Run
 * from this directory: "php derive.php data" writes the data files xmlsec1 encrypts, from the response
 * ../behaviour/response-signed-assertion-accepted.xml; "php derive.php hostile" writes the hostile fixtures, each the
 * output of xmlsec1 with the one change its name says. Every replacement is refused unless the text it replaces is
 * found exactly once, so that a run writes the committed bytes again or nothing.
 */

const SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const IV_BYTES = 12;

$mode = $argv[1] ?? '';
if ($mode !== 'data' && $mode !== 'hostile') {
    fwrite(STDERR, "Usage: php derive.php data|hostile\n");
    exit(1);
}

/** The bytes of $path, relative to this directory. */
$read = static function (string $path): string {
    $bytes = file_get_contents(__DIR__ . '/' . $path);
    if ($bytes === false) {
        fwrite(STDERR, "Cannot read {$path}\n");
        exit(1);
    }

    return $bytes;
};

/** $search replaced by $replace in $subject, where it is found exactly once. */
$replace = static function (string $search, string $replace, string $subject): string {
    if (substr_count($subject, $search) !== 1) {
        fwrite(STDERR, "Not found exactly once: {$search}\n");
        exit(1);
    }

    return str_replace($search, $replace, $subject);
};

/** $pattern replaced in $subject by what $callback returns, where it matches exactly once. */
$replaceMatch = static function (string $pattern, callable $callback, string $subject): string {
    $result = preg_replace_callback($pattern, $callback, $subject, -1, $count);
    if ($result === null || $count !== 1) {
        fwrite(STDERR, "Not matched exactly once: {$pattern}\n");
        exit(1);
    }

    return $result;
};

/** The one match of $pattern in $subject. */
$extract = static function (string $pattern, string $subject): string {
    if (preg_match_all($pattern, $subject, $matches) !== 1) {
        fwrite(STDERR, "Not matched exactly once: {$pattern}\n");
        exit(1);
    }

    return $matches[0][0];
};

$write = static function (string $path, string $bytes): void {
    // ended by a line break, as xmlsec1 ends what it writes, so that the decryption of a vector is its data file
    if (file_put_contents(__DIR__ . '/' . $path, rtrim($bytes, "\n") . "\n") === false) {
        exit(1);
    }
};

if ($mode === 'data') {
    $clear = $read('../behaviour/response-signed-assertion-accepted.xml');

    // the signed assertion inside a saml:EncryptedAssertion, the saml prefix declared on the assertion itself:
    // xmlsec1 encrypts the element with the declarations it carries and none it inherits (enc.md section 13), and the
    // exclusive canonical form of the assertion renders that declaration on it wherever it stands, so that its
    // signature is unchanged
    $signed = $replace(
        "\n  <saml:Assertion ID=\"_assertion\"",
        "\n  <saml:EncryptedAssertion><saml:Assertion xmlns:saml=\"" . SAML . '" ID="_assertion"',
        $clear,
    );
    $signed = $replace("\n  </saml:Assertion>\n", "\n  </saml:Assertion></saml:EncryptedAssertion>\n", $signed);
    $write('response-signed-assertion.data.xml', $signed);

    // the same assertion without its signature
    $unsigned = $replaceMatch('~<ds:Signature .*?</ds:Signature>~s', static fn (): string => '', $signed);
    $write('response-unsigned-assertion.data.xml', $unsigned);

    // the unsigned assertion, the response carrying the template of an enveloped signature after its Issuer, which
    // xmlsec1 fills once the assertion is encrypted
    $write('response-signed-response.data.xml', $replace(
        "</saml:Issuer>\n  <samlp:Status>",
        '</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>'
        . '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        . '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        . '<ds:Reference URI="#_response"><ds:Transforms>'
        . '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        . '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>'
        . '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue></ds:DigestValue>'
        . '</ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue></ds:Signature>'
        . "\n  <samlp:Status>",
        $unsigned,
    ));

    // in place of the assertion, the response in clear, whose own assertion is the signed one: what the plaintext of
    // a saml:EncryptedAssertion must not be
    $inside = $replace(' ID="_response"', ' ID="_response-inside"', $extract('~<samlp:Response .*</samlp:Response>~s', $clear));
    $write('response-not-an-assertion.data.xml', $replaceMatch(
        '~<saml:Assertion xmlns:saml="[^"]*" ID="_assertion".*</saml:Assertion>~s',
        static fn (): string => $inside,
        $signed,
    ));

    exit(0);
}

$vector = $read('response-encrypted-signed-assertion-accepted.xml');
$signedOver = $read('response-signed-over-encrypted-assertion-accepted.xml');

/** The cipher value of the content, the last xenc:CipherValue of the document, decoded, changed by $change. */
$content = static function (string $document, callable $change) use ($replaceMatch): string {
    return $replaceMatch(
        '~(<xenc:CipherValue>)([^<]*)(</xenc:CipherValue>\s*</xenc:CipherData>\s*</xenc:EncryptedData>)~',
        static function (array $match) use ($change): string {
            $bytes = base64_decode((string) preg_replace('~\s+~', '', $match[2]), true);
            if ($bytes === false) {
                exit(1);
            }

            return $match[1] . rtrim(chunk_split(base64_encode($change($bytes)), 64, "\n"), "\n") . $match[3];
        },
        $document,
    );
};

/** The first byte of the ciphertext, right after the IV, flipped. */
$flip = static fn (string $bytes): string => substr_replace($bytes, chr(ord($bytes[IV_BYTES]) ^ 0x01), IV_BYTES, 1);

// the three failures of E-3, the response unsigned so that nothing but the decryption sees them
$write('response-encrypted-ciphertext-altered-refused.xml', $content($vector, $flip));
$write('response-encrypted-tag-truncated-refused.xml', $content($vector, static fn (string $bytes): string => substr($bytes, 0, -1)));

// the ciphertext altered under the signature of the response: refused by the signature, before any decryption
$write('response-signed-over-encrypted-assertion-ciphertext-altered-refused.xml', $content($signedOver, $flip));

// the response without its Issuer, which E17 requires when an assertion is encrypted
$write('response-encrypted-without-issuer-refused.xml', $replace(
    "\n  <saml:Issuer>https://idp.example.com/saml</saml:Issuer>",
    '',
    $vector,
));

// the structure of the saml:EncryptedAssertion
$data = $extract('~<xenc:EncryptedData .*</xenc:EncryptedData>~s', $vector);
$write('response-encrypted-assertion-empty-refused.xml', $replace(
    '<saml:EncryptedAssertion>' . $data . '</saml:EncryptedAssertion>',
    '<saml:EncryptedAssertion></saml:EncryptedAssertion>',
    $vector,
));
$write('response-encrypted-assertion-two-encrypted-data-refused.xml', $replace(
    $data . '</saml:EncryptedAssertion>',
    $data . $data . '</saml:EncryptedAssertion>',
    $vector,
));
$key = $extract('~<xenc:EncryptedKey>.*</xenc:EncryptedKey>~s', $vector);
$write('response-encrypted-key-as-a-sibling-refused.xml', $replace(
    $data . '</saml:EncryptedAssertion>',
    $replace($key, '', $data)
    . '<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
    . substr($key, strlen('<xenc:EncryptedKey'))
    . '</saml:EncryptedAssertion>',
    $vector,
));

// next to the saml:EncryptedAssertion, the assertion in clear, signed: one assertion, in clear or encrypted (M-4)
$clear = $read('../behaviour/response-signed-assertion-accepted.xml');
$assertion = $extract('~<saml:Assertion ID="_assertion".*</saml:Assertion>~s', $clear);
$write('response-encrypted-next-to-an-assertion-refused.xml', $replace(
    '</saml:EncryptedAssertion>',
    '</saml:EncryptedAssertion>' . "\n  " . $assertion,
    $vector,
));

// a failure holding a saml:EncryptedAssertion (M-13)
$write('response-encrypted-in-a-failure-refused.xml', $replace(
    'urn:oasis:names:tc:SAML:2.0:status:Success',
    'urn:oasis:names:tc:SAML:2.0:status:Responder',
    $vector,
));
