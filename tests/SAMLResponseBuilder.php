<?php
namespace Tests;

use DOMDocument;
use DOMElement;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * Builds ADFS-like SAML responses for tests, signed with throwaway keys.
 *
 * Defaults describe a valid response for the audience AUDIENCE, checked at
 * time NOW. Each setter returns the builder, so tests change only what they
 * need, e.g. SAMLResponseBuilder::create()->signResponse(true)->encoded().
 */
class SAMLResponseBuilder {
    public const AUDIENCE = 'https://app.example.com/login';
    public const ISSUER = 'http://adfs.example.com/adfs/services/trust';
    public const NOW = 1800000000;
    public const RECIPIENT = 'https://app.example.com/apis/verify';
    public const UPN = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn';

    private static array $keys = [];

    private string $appId = 'My_App';
    private string $assertionId = '_assertion1';
    private ?array $attributes = null;
    private string $audience = self::AUDIENCE;
    private string $digestAlgorithm = XMLSecurityDSig::SHA256;
    private string $issuer = self::ISSUER;
    private string $keyName = 'adfs';
    private array $mutators = [];
    private ?string $nameId = 'user@example.com';
    private int $notBefore = self::NOW - 60;
    private int $notOnOrAfter = self::NOW + 3600;
    private string $recipient = self::RECIPIENT;
    private ?string $responseInResponseTo = null;
    private string $responseId = '_response1';
    private ?string $scdInResponseTo = null;
    private int $scdNotOnOrAfter = self::NOW + 300;
    private bool $signAssertion = true;
    private string $signatureAlgorithm = XMLSecurityKey::RSA_SHA256;
    private bool $signResponse = false;
    private string $status = 'urn:oasis:names:tc:SAML:2.0:status:Success';
    private string $username = 'user@example.com';

    /**
     * Returns the PEM certificate of a named test key, creating it on first use.
     */
    public static function certificate(string $name = 'adfs'): string {
        return self::key($name)['cert'];
    }

    public static function create(): self {
        return new self();
    }

    /**
     * Base64 of an arbitrary XML string.
     */
    public static function encode(string $xml): string {
        return base64_encode($xml);
    }

    /**
     * Returns the response XML.
     */
    public function build(): string {
        $doc = new DOMDocument();
        $doc->loadXML($this->unsignedXml());
        $assertion = $doc->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Assertion')->item(0);

        if ($this->signAssertion && $assertion !== null) {
            $this->sign($assertion);
        }

        if ($this->signResponse) {
            $this->sign($doc->documentElement);
        }

        foreach ($this->mutators as $mutator) {
            $mutator($doc);
        }

        return $doc->saveXML();
    }

    /**
     * Returns the response XML, base64-encoded as ADFS posts it.
     */
    public function encoded(): string {
        return base64_encode($this->build());
    }

    /**
     * Changes the document after it was signed.
     *
     * @param callable $mutator Receives the DOMDocument.
     */
    public function mutate(callable $mutator): self {
        $this->mutators[] = $mutator;

        return $this;
    }

    public function withAppId(string $appId): self {
        $this->appId = $appId;

        return $this;
    }

    public function withAssertionId(string $id): self {
        $this->assertionId = $id;

        return $this;
    }

    /**
     * @param array<string, string[]> $attributes Replaces the default attributes.
     */
    public function withAttributes(array $attributes): self {
        $this->attributes = $attributes;

        return $this;
    }

    public function withAudience(string $audience): self {
        $this->audience = $audience;

        return $this;
    }

    public function withConditions(int $notBefore, int $notOnOrAfter): self {
        $this->notBefore = $notBefore;
        $this->notOnOrAfter = $notOnOrAfter;

        return $this;
    }

    public function withIssuer(string $issuer): self {
        $this->issuer = $issuer;

        return $this;
    }

    public function withNameId(?string $nameId): self {
        $this->nameId = $nameId;

        return $this;
    }

    public function withRecipient(string $recipient): self {
        $this->recipient = $recipient;

        return $this;
    }

    /**
     * Sets InResponseTo separately on the Response and in the assertion.
     */
    public function withInResponseTo(?string $response, ?string $subjectConfirmation): self {
        $this->responseInResponseTo = $response;
        $this->scdInResponseTo = $subjectConfirmation;

        return $this;
    }

    public function withSha1(): self {
        $this->signatureAlgorithm = XMLSecurityKey::RSA_SHA1;
        $this->digestAlgorithm = XMLSecurityDSig::SHA1;

        return $this;
    }

    public function withSigningKey(string $name): self {
        $this->keyName = $name;

        return $this;
    }

    public function withStatus(string $status): self {
        $this->status = $status;

        return $this;
    }

    public function withSubjectConfirmationExpiry(int $notOnOrAfter): self {
        $this->scdNotOnOrAfter = $notOnOrAfter;

        return $this;
    }

    public function withUsername(string $username): self {
        $this->username = $username;

        return $this;
    }

    public function signAssertion(bool $sign): self {
        $this->signAssertion = $sign;

        return $this;
    }

    public function signResponse(bool $sign): self {
        $this->signResponse = $sign;

        return $this;
    }

    /**
     * Returns the XML before signing.
     */
    public function unsignedXml(): string {
        $time = fn (int $t) => gmdate('Y-m-d\TH:i:s', $t).'.000Z';
        $esc = fn (string $s) => htmlspecialchars($s, ENT_XML1 | ENT_QUOTES);
        $responseIrt = $this->responseInResponseTo ?? $this->appId;
        $scdIrt = $this->scdInResponseTo ?? $this->appId;
        $attributes = $this->attributes ?? [self::UPN => [$this->username]];
        $attributeXml = '';

        foreach ($attributes as $name => $values) {
            $attributeXml .= '<Attribute Name="'.$esc($name).'">';

            foreach ($values as $value) {
                $attributeXml .= '<AttributeValue>'.$esc($value).'</AttributeValue>';
            }
            $attributeXml .= '</Attribute>';
        }
        $nameIdXml = $this->nameId !== null
            ? '<NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">'.$esc($this->nameId).'</NameID>'
            : '';
        $isSuccess = $this->status === 'urn:oasis:names:tc:SAML:2.0:status:Success';

        $assertion = !$isSuccess ? '' :
            '<Assertion ID="'.$esc($this->assertionId).'" IssueInstant="'.$time(self::NOW).'" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">'
            .'<Issuer>'.$esc($this->issuer).'</Issuer>'
            .'<Subject>'.$nameIdXml
            .'<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            .'<SubjectConfirmationData '.($scdIrt !== '' ? 'InResponseTo="'.$esc($scdIrt).'" ' : '')
            .'NotOnOrAfter="'.$time($this->scdNotOnOrAfter).'" Recipient="'.$esc($this->recipient).'" />'
            .'</SubjectConfirmation></Subject>'
            .'<Conditions NotBefore="'.$time($this->notBefore).'" NotOnOrAfter="'.$time($this->notOnOrAfter).'">'
            .'<AudienceRestriction><Audience>'.$esc($this->audience).'</Audience></AudienceRestriction>'
            .'</Conditions>'
            .'<AttributeStatement>'.$attributeXml.'</AttributeStatement>'
            .'<AuthnStatement AuthnInstant="'.$time(self::NOW).'" SessionIndex="'.$esc($this->assertionId).'">'
            .'<AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef></AuthnContext>'
            .'</AuthnStatement>'
            .'</Assertion>';

        return '<samlp:Response ID="'.$esc($this->responseId).'" Version="2.0" IssueInstant="'.$time(self::NOW).'"'
            .' Destination="'.$esc($this->recipient).'" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified"'
            .($responseIrt !== '' ? ' InResponseTo="'.$esc($responseIrt).'"' : '')
            .' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            .'<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">'.$esc($this->issuer).'</Issuer>'
            .'<samlp:Status><samlp:StatusCode Value="'.$esc($this->status).'" /></samlp:Status>'
            .$assertion
            .'</samlp:Response>';
    }

    private static function key(string $name): array {
        if (!isset(self::$keys[$name])) {
            $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            $csr = openssl_csr_new(['commonName' => 'ADFS Signing - '.$name], $private, ['digest_alg' => 'sha256']);
            $cert = openssl_csr_sign($csr, null, $private, 1, ['digest_alg' => 'sha256']);
            openssl_pkey_export($private, $privatePem);
            openssl_x509_export($cert, $certPem);
            self::$keys[$name] = ['private' => $privatePem, 'cert' => $certPem];
        }

        return self::$keys[$name];
    }

    /**
     * Signs an element the way ADFS does: enveloped signature placed right
     * after the Issuer, exclusive canonicalization, certificate in KeyInfo.
     */
    private function sign(DOMElement $element): void {
        $keys = self::key($this->keyName);
        $dsig = new XMLSecurityDSig();
        $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $dsig->addReference(
            $element,
            $this->digestAlgorithm,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
            ['id_name' => 'ID', 'overwrite' => false]
        );
        $key = new XMLSecurityKey($this->signatureAlgorithm, ['type' => 'private']);
        $key->loadKey($keys['private']);
        $dsig->sign($key);
        $dsig->add509Cert($keys['cert']);
        $issuer = $element->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')->item(0);
        $dsig->insertSignature($element, $issuer !== null ? $issuer->nextSibling : $element->firstChild);
    }
}
