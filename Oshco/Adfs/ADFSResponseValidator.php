<?php
namespace Oshco\Adfs;

use DateTimeImmutable;
use DOMDocument;
use DOMElement;
use DOMXPath;
use Exception;
use InvalidArgumentException;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * Verifies that a SAML response really comes from ADFS and is meant for this
 * application.
 *
 * A response is accepted only if all of the following hold:
 * - Its status is Success and it holds exactly one unencrypted Assertion.
 * - The Assertion, or the whole Response, carries an XML signature that
 *   verifies against one of the configured ADFS token-signing certificates.
 *   Any certificate embedded in the message is ignored.
 * - The signature references exactly the element it is attached to, using
 *   only allowed algorithms and transforms (blocks signature wrapping).
 * - The assertion is within its validity window, is addressed to the
 *   configured audience, and has a bearer subject confirmation that has not
 *   expired.
 * - Optionally, the issuer and the recipient match the configured values.
 *
 * Replay protection (rejecting an assertion ID that was already used) needs
 * storage and is left to the application; see
 * ADFSVerificationService::isAssertionReplayed().
 */
class ADFSResponseValidator {
    /**
     * Default allowed clock difference between ADFS and this server, in seconds.
     */
    public const DEFAULT_CLOCK_SKEW = 180;

    private const ALLOWED_C14N = [
        XMLSecurityDSig::EXC_C14N,
        XMLSecurityDSig::EXC_C14N_COMMENTS,
        XMLSecurityDSig::C14N,
        XMLSecurityDSig::C14N_COMMENTS,
    ];
    private const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
    private const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    private bool $allowSha1 = false;
    private string $audience;
    /**
     * @var string[]
     */
    private array $certificates = [];
    private int $clockSkew = self::DEFAULT_CLOCK_SKEW;
    private ?int $currentTime = null;
    private ?string $issuer = null;
    private ?string $recipient = null;
    private ?string $usernameAttribute = null;

    /**
     * Creates new instance of the class.
     *
     * @param string|string[] $certificates The ADFS token-signing certificate,
     * or several during a certificate rollover. Each can be a PEM certificate
     * or the base64 body only, as found in the ADFS federation metadata.
     * @param string $audience The identifier of this application as configured
     * in ADFS (the relying party identifier). This is the value sent as the
     * Issuer of the SAML request, usually the application URL.
     *
     * @throws InvalidArgumentException If no certificate is given, a
     * certificate cannot be read, or the audience is empty.
     */
    public function __construct(string|array $certificates, string $audience) {
        $certificates = is_array($certificates) ? $certificates : [$certificates];

        foreach ($certificates as $certificate) {
            $this->certificates[] = self::normalizeCertificate($certificate);
        }

        if (count($this->certificates) === 0) {
            throw new InvalidArgumentException('At least one ADFS signing certificate is required.');
        }
        $audience = trim($audience);

        if ($audience === '') {
            throw new InvalidArgumentException('The audience must not be empty.');
        }
        $this->audience = $audience;
    }

    /**
     * Returns the expected audience.
     *
     * @return string
     */
    public function getAudience(): string {
        return $this->audience;
    }

    /**
     * Returns the allowed clock difference, in seconds.
     *
     * @return int
     */
    public function getClockSkew(): int {
        return $this->clockSkew;
    }

    /**
     * Returns the expected issuer.
     *
     * @return string|null Null if the issuer is not checked.
     */
    public function getIssuer(): ?string {
        return $this->issuer;
    }

    /**
     * Returns the expected recipient.
     *
     * @return string|null Null if the recipient is not checked.
     */
    public function getRecipient(): ?string {
        return $this->recipient;
    }

    /**
     * Returns the name of the attribute that holds the username.
     *
     * @return string|null Null if the first attribute value is used.
     */
    public function getUsernameAttribute(): ?string {
        return $this->usernameAttribute;
    }

    /**
     * Allows or rejects signatures and digests that use SHA-1.
     *
     * SHA-1 is rejected by default. Enable it only for an ADFS relying party
     * that cannot be switched to SHA-256.
     *
     * @param bool $allow
     */
    public function setAllowSha1(bool $allow): void {
        $this->allowSha1 = $allow;
    }

    /**
     * Sets the allowed clock difference between ADFS and this server.
     *
     * @param int $seconds A value from 0 to 600.
     *
     * @throws InvalidArgumentException If the value is out of range.
     */
    public function setClockSkew(int $seconds): void {
        if ($seconds < 0 || $seconds > 600) {
            throw new InvalidArgumentException('Clock skew must be between 0 and 600 seconds.');
        }
        $this->clockSkew = $seconds;
    }

    /**
     * Sets the time used for validity checks.
     *
     * @param int|null $timestamp A Unix timestamp, or null to use the current time.
     */
    public function setCurrentTime(?int $timestamp): void {
        $this->currentTime = $timestamp;
    }

    /**
     * Sets the expected issuer of the assertion.
     *
     * For ADFS this is usually 'http://{adfs-host}/adfs/services/trust'.
     *
     * @param string|null $issuer The issuer, or null to skip the check.
     */
    public function setIssuer(?string $issuer): void {
        $this->issuer = $issuer !== null && trim($issuer) !== '' ? trim($issuer) : null;
    }

    /**
     * Sets the expected recipient of the assertion.
     *
     * This is the URL of the endpoint that receives the response from ADFS.
     *
     * @param string|null $recipient The URL, or null to skip the check.
     */
    public function setRecipient(?string $recipient): void {
        $this->recipient = $recipient !== null && trim($recipient) !== '' ? trim($recipient) : null;
    }

    /**
     * Sets the name of the attribute that holds the username.
     *
     * When not set, the first attribute value of the assertion is used, as in
     * version 2. Setting it is recommended, so that changing the order of the
     * claim rules in ADFS cannot change who is signed in.
     *
     * @param string|null $name e.g.
     * 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn'.
     */
    public function setUsernameAttribute(?string $name): void {
        $this->usernameAttribute = $name !== null && trim($name) !== '' ? trim($name) : null;
    }

    /**
     * Validates a response and, on success, marks it as verified.
     *
     * After this method returns, the getters of the response return values
     * read from the signed assertion.
     *
     * @param ADFSResponse $response The response to check.
     *
     * @throws SAMLValidationException If any check fails.
     */
    public function validate(ADFSResponse $response): void {
        if (!$response->isSuccess()) {
            throw new SAMLValidationException(SAMLValidationException::REASON_STATUS_NOT_SUCCESS, 'SAML response status is not Success: '.$response->getStatusCode());
        }
        $doc = $response->getDocument();
        $xpath = ADFSResponse::createXPath($doc);
        $root = $doc->documentElement;

        $this->checkStructure($xpath, $root);
        $assertion = $xpath->query('saml:Assertion', $root)->item(0);

        // Signatures. A signature that is present must be valid; at least one
        // of the two must be present. The Response signature covers the
        // Assertion too, since the Assertion is a descendant.
        $assertionSigned = $this->checkSignatureOf($response->getRawXML(), 'assertion', $assertion);
        $responseSigned = $this->checkSignatureOf($response->getRawXML(), 'response', $root);

        if (!$assertionSigned && !$responseSigned) {
            throw new SAMLValidationException(SAMLValidationException::REASON_UNSIGNED, 'Neither the SAML Response nor the Assertion is signed.');
        }
        $now = $this->currentTime ?? time();
        $issuer = trim($xpath->evaluate('string(saml:Issuer)', $assertion));

        if ($this->issuer !== null && $issuer !== $this->issuer) {
            throw new SAMLValidationException(SAMLValidationException::REASON_ISSUER_MISMATCH, 'Unexpected assertion issuer: '.$issuer);
        }
        $conditionsExpiry = $this->checkConditions($xpath, $assertion, $now);
        [$confirmationExpiry, $confirmationInResponseTo] = $this->checkSubjectConfirmation($xpath, $assertion, $now);

        // The Response's InResponseTo is outside the Assertion, so it is only
        // covered when the Response itself is signed. Prefer the copy inside
        // the Assertion, and reject a response where the two disagree.
        $responseInResponseTo = $root->getAttribute('InResponseTo');

        if ($confirmationInResponseTo !== '' && $responseInResponseTo !== '' && $confirmationInResponseTo !== $responseInResponseTo) {
            throw new SAMLValidationException(SAMLValidationException::REASON_IN_RESPONSE_TO_MISMATCH, 'InResponseTo of the Response does not match the Assertion.');
        }
        $inResponseTo = $confirmationInResponseTo !== '' ? $confirmationInResponseTo : ($responseSigned ? $responseInResponseTo : '');

        $attributes = $this->readAttributes($xpath, $assertion);
        $username = $this->readUsername($xpath, $assertion, $attributes);
        $nameIdNode = $xpath->query('saml:Subject/saml:NameID', $assertion)->item(0);

        $response->setVerifiedClaims([
            'username' => $username,
            'appName' => str_replace('_', ' ', $inResponseTo),
            'assertionId' => $assertion->getAttribute('ID'),
            'issuer' => $issuer,
            'nameId' => $nameIdNode instanceof DOMElement ? trim($nameIdNode->textContent) : null,
            'nameIdFormat' => $nameIdNode instanceof DOMElement && $nameIdNode->hasAttribute('Format') ? $nameIdNode->getAttribute('Format') : null,
            'attributes' => $attributes,
            'notOnOrAfter' => $conditionsExpiry !== null ? min($conditionsExpiry, $confirmationExpiry) : $confirmationExpiry,
        ]);
    }

    /**
     * Checks Conditions: the validity window and the audience.
     *
     * @return int|null The NotOnOrAfter time, if present.
     */
    private function checkConditions(DOMXPath $xpath, DOMElement $assertion, int $now): ?int {
        $conditions = $xpath->query('saml:Conditions', $assertion);

        if ($conditions->length !== 1) {
            throw new SAMLValidationException(SAMLValidationException::REASON_AUDIENCE_MISMATCH, 'Assertion must contain exactly one Conditions element.');
        }
        $node = $conditions->item(0);
        $notBefore = $this->readTime($node, 'NotBefore');
        $notOnOrAfter = $this->readTime($node, 'NotOnOrAfter');

        if ($notBefore !== null && $now + $this->clockSkew < $notBefore) {
            throw new SAMLValidationException(SAMLValidationException::REASON_NOT_YET_VALID, 'Assertion is not yet valid.');
        }

        if ($notOnOrAfter !== null && $now - $this->clockSkew >= $notOnOrAfter) {
            throw new SAMLValidationException(SAMLValidationException::REASON_EXPIRED, 'Assertion has expired.');
        }

        // Without this check, an assertion that ADFS issued to any other
        // relying party could be replayed here.
        $restrictions = $xpath->query('saml:AudienceRestriction', $node);

        if ($restrictions->length === 0) {
            throw new SAMLValidationException(SAMLValidationException::REASON_AUDIENCE_MISMATCH, 'Assertion has no audience restriction.');
        }

        // Every AudienceRestriction must include this application.
        foreach ($restrictions as $restriction) {
            $found = false;

            foreach ($xpath->query('saml:Audience', $restriction) as $audience) {
                if (trim($audience->textContent) === $this->audience) {
                    $found = true;
                    break;
                }
            }

            if (!$found) {
                throw new SAMLValidationException(SAMLValidationException::REASON_AUDIENCE_MISMATCH, 'Assertion is not intended for audience '.$this->audience.'.');
            }
        }

        return $notOnOrAfter;
    }

    /**
     * Verifies the signature attached directly to an element, if any.
     *
     * The check runs on a separate copy of the document, because xmlseclibs
     * removes the signature from the document it validates.
     *
     * @param string $xml The raw response XML.
     * @param string $target 'response' or 'assertion'.
     * @param DOMElement $element The element in the original document, used
     * to find out whether it has a signature.
     *
     * @return bool False if the element has no signature, true if it has a valid one.
     *
     * @throws SAMLValidationException If a signature is present but invalid.
     */
    private function checkSignatureOf(string $xml, string $target, DOMElement $element): bool {
        $originalXpath = ADFSResponse::createXPath($element->ownerDocument);
        $count = $originalXpath->query('ds:Signature', $element)->length;

        if ($count === 0) {
            return false;
        }

        if ($count > 1) {
            throw new SAMLValidationException(SAMLValidationException::REASON_UNSUPPORTED_SIGNATURE, 'More than one signature on the '.$target.'.');
        }

        $copy = ADFSResponse::parseXml($xml);
        $xpath = ADFSResponse::createXPath($copy);
        $signed = $target === 'response'
            ? $copy->documentElement
            : $xpath->query('saml:Assertion', $copy->documentElement)->item(0);
        $signature = $xpath->query('ds:Signature', $signed)->item(0);
        [$signatureAlgorithm] = $this->checkSignedInfo($xpath, $signature, $signed);

        try {
            $dsig = new XMLSecurityDSig();
            $dsig->idKeys = ['ID'];
            // Set the node directly: locateSignature() searches descendants and
            // would return the Assertion's signature when checking the Response.
            $dsig->sigNode = $signature;

            if ($dsig->canonicalizeSignedInfo() === null) {
                throw new Exception('SignedInfo could not be canonicalized.');
            }
            $dsig->validateReference();
            $validated = $dsig->getValidatedNodes() ?? [];

            if (count($validated) !== 1 || !reset($validated)->isSameNode($signed)) {
                throw new Exception('Signature does not reference the signed element.');
            }

            foreach ($this->certificates as $certificate) {
                // The key type comes from the allow-list checked above, never
                // from KeyInfo, so a message cannot pick HMAC or its own key.
                $key = new XMLSecurityKey($signatureAlgorithm, ['type' => 'public']);
                $key->loadKey($certificate, false, true);

                if ($dsig->verify($key) === 1) {
                    return true;
                }
            }
        } catch (Exception $e) {
            throw new SAMLValidationException(SAMLValidationException::REASON_INVALID_SIGNATURE, 'Invalid signature on the '.$target.': '.$e->getMessage(), $e);
        }

        throw new SAMLValidationException(SAMLValidationException::REASON_INVALID_SIGNATURE, 'Signature on the '.$target.' does not match any configured certificate.');
    }

    /**
     * Checks the SignedInfo of a signature against the allowed structure and
     * algorithms.
     *
     * @return array The signature algorithm as the only element.
     */
    private function checkSignedInfo(DOMXPath $xpath, DOMElement $signature, DOMElement $signed): array {
        $fail = function (string $message) {
            throw new SAMLValidationException(SAMLValidationException::REASON_UNSUPPORTED_SIGNATURE, $message);
        };
        $signedInfo = $xpath->query('ds:SignedInfo', $signature);

        if ($signedInfo->length !== 1) {
            $fail('Signature must contain exactly one SignedInfo.');
        }
        $signedInfo = $signedInfo->item(0);

        if (!in_array($xpath->evaluate('string(ds:CanonicalizationMethod/@Algorithm)', $signedInfo), self::ALLOWED_C14N, true)) {
            $fail('Canonicalization method is not allowed.');
        }
        $signatureAlgorithm = $xpath->evaluate('string(ds:SignatureMethod/@Algorithm)', $signedInfo);
        $allowedSignatures = [XMLSecurityKey::RSA_SHA256, XMLSecurityKey::RSA_SHA384, XMLSecurityKey::RSA_SHA512];
        $allowedDigests = [XMLSecurityDSig::SHA256, XMLSecurityDSig::SHA384, XMLSecurityDSig::SHA512];

        if ($this->allowSha1) {
            $allowedSignatures[] = XMLSecurityKey::RSA_SHA1;
            $allowedDigests[] = XMLSecurityDSig::SHA1;
        }

        if (!in_array($signatureAlgorithm, $allowedSignatures, true)) {
            $fail('Signature algorithm is not allowed: '.$signatureAlgorithm);
        }
        $references = $xpath->query('ds:Reference', $signedInfo);

        if ($references->length !== 1) {
            $fail('Signature must contain exactly one Reference.');
        }
        $reference = $references->item(0);
        $id = $signed->getAttribute('ID');

        if ($id === '' || $reference->getAttribute('URI') !== '#'.$id) {
            $fail('Signature Reference does not point to the signed element.');
        }

        if (!in_array($xpath->evaluate('string(ds:DigestMethod/@Algorithm)', $reference), $allowedDigests, true)) {
            $fail('Digest algorithm is not allowed.');
        }
        $transforms = $xpath->query('ds:Transforms/ds:Transform', $reference);

        if ($transforms->length > 2) {
            $fail('Too many transforms.');
        }

        // XPath and XSLT transforms could sign only part of the element.
        foreach ($transforms as $transform) {
            $algorithm = $transform->getAttribute('Algorithm');

            if ($algorithm !== self::ENVELOPED && !in_array($algorithm, self::ALLOWED_C14N, true)) {
                $fail('Transform is not allowed: '.$algorithm);
            }
        }

        return [$signatureAlgorithm];
    }

    /**
     * Checks the document structure needed to read the assertion safely.
     */
    private function checkStructure(DOMXPath $xpath, DOMElement $root): void {
        if ($xpath->query('//saml:EncryptedAssertion')->length > 0) {
            throw new SAMLValidationException(SAMLValidationException::REASON_ENCRYPTED_ASSERTION, 'Encrypted assertions are not supported.');
        }

        // Exactly one Assertion anywhere in the document, as a direct child of
        // the Response. A second one elsewhere is a signature wrapping attempt.
        if ($xpath->query('//saml:Assertion')->length !== 1 || $xpath->query('saml:Assertion', $root)->length !== 1) {
            throw new SAMLValidationException(SAMLValidationException::REASON_INVALID_ASSERTION_COUNT, 'SAML response must contain exactly one Assertion.');
        }
        $ids = [];

        foreach ($xpath->query('//@ID | //@Id | //@id') as $attribute) {
            if (isset($ids[$attribute->value])) {
                throw new SAMLValidationException(SAMLValidationException::REASON_DUPLICATE_ID, 'Duplicate ID in SAML response: '.$attribute->value);
            }
            $ids[$attribute->value] = true;
        }
    }

    /**
     * Checks that at least one bearer subject confirmation is usable.
     *
     * @return array The NotOnOrAfter time and InResponseTo value of the
     * accepted confirmation.
     */
    private function checkSubjectConfirmation(DOMXPath $xpath, DOMElement $assertion, int $now): array {
        $lastError = SAMLValidationException::REASON_INVALID_SUBJECT_CONFIRMATION;

        foreach ($xpath->query('saml:Subject/saml:SubjectConfirmation', $assertion) as $confirmation) {
            if ($confirmation->getAttribute('Method') !== self::BEARER) {
                continue;
            }
            $data = $xpath->query('saml:SubjectConfirmationData', $confirmation)->item(0);

            if (!$data instanceof DOMElement) {
                continue;
            }
            $notOnOrAfter = $this->readTime($data, 'NotOnOrAfter');

            if ($notOnOrAfter === null) {
                continue;
            }

            if ($now - $this->clockSkew >= $notOnOrAfter) {
                $lastError = SAMLValidationException::REASON_EXPIRED;
                continue;
            }
            $notBefore = $this->readTime($data, 'NotBefore');

            if ($notBefore !== null && $now + $this->clockSkew < $notBefore) {
                $lastError = SAMLValidationException::REASON_NOT_YET_VALID;
                continue;
            }

            if ($this->recipient !== null && $data->getAttribute('Recipient') !== $this->recipient) {
                $lastError = SAMLValidationException::REASON_RECIPIENT_MISMATCH;
                continue;
            }

            return [$notOnOrAfter, $data->getAttribute('InResponseTo')];
        }

        throw new SAMLValidationException($lastError, 'No valid bearer subject confirmation in the assertion.');
    }

    /**
     * Converts a certificate to PEM and checks that it can be read.
     */
    private static function normalizeCertificate(string $certificate): string {
        $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $certificate);

        if ($body === '' || base64_decode($body, true) === false) {
            throw new InvalidArgumentException('Invalid ADFS signing certificate.');
        }
        $pem = "-----BEGIN CERTIFICATE-----\n".chunk_split($body, 64, "\n")."-----END CERTIFICATE-----\n";

        if (@openssl_x509_read($pem) === false) {
            throw new InvalidArgumentException('Invalid ADFS signing certificate.');
        }

        return $pem;
    }

    /**
     * Reads all attributes of the assertion.
     *
     * @return array<string, string[]>
     */
    private function readAttributes(DOMXPath $xpath, DOMElement $assertion): array {
        $attributes = [];

        foreach ($xpath->query('saml:AttributeStatement/saml:Attribute', $assertion) as $attribute) {
            $name = $attribute->getAttribute('Name');

            foreach ($xpath->query('saml:AttributeValue', $attribute) as $value) {
                $attributes[$name][] = trim($value->textContent);
            }
        }

        return $attributes;
    }

    /**
     * Reads a SAML time attribute.
     *
     * @return int|null A Unix timestamp, or null if the attribute is missing.
     *
     * @throws SAMLValidationException If the value is not a valid UTC time.
     */
    private function readTime(DOMElement $node, string $attribute): ?int {
        if (!$node->hasAttribute($attribute)) {
            return null;
        }
        $value = $node->getAttribute($attribute);

        if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/', $value) !== 1) {
            throw new SAMLValidationException(SAMLValidationException::REASON_MALFORMED, 'Invalid time value in '.$attribute.'.');
        }

        return (new DateTimeImmutable($value))->getTimestamp();
    }

    /**
     * Reads the username from the verified attributes.
     *
     * @param array<string, string[]> $attributes
     */
    private function readUsername(DOMXPath $xpath, DOMElement $assertion, array $attributes): string {
        if ($this->usernameAttribute !== null) {
            $value = $attributes[$this->usernameAttribute][0] ?? '';
        } else {
            $node = $xpath->query('saml:AttributeStatement/saml:Attribute/saml:AttributeValue', $assertion)->item(0);
            $value = $node !== null ? trim($node->textContent) : '';
        }

        if ($value === '') {
            throw new SAMLValidationException(SAMLValidationException::REASON_MISSING_USERNAME, 'The username attribute is missing from the assertion.');
        }

        return strtolower($value);
    }
}
