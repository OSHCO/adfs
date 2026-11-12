<?php
namespace Tests;

use DOMDocument;
use DOMXPath;
use InvalidArgumentException;
use Oshco\Adfs\ADFSResponse;
use Oshco\Adfs\ADFSResponseValidator;
use Oshco\Adfs\SAMLValidationException;
use PHPUnit\Framework\TestCase;

class ADFSResponseValidatorTest extends TestCase {

    // ---- Accepted responses -------------------------------------------------

    public function testSignedAssertionIsAccepted() {
        $resp = $this->validate(SAMLResponseBuilder::create());

        $this->assertTrue($resp->isVerified());
        $this->assertSame('user@example.com', $resp->getUserName());
        $this->assertSame('My App', $resp->getAppName());
        $this->assertSame('_assertion1', $resp->getAssertionId());
        $this->assertSame(SAMLResponseBuilder::ISSUER, $resp->getIssuer());
        $this->assertSame('user@example.com', $resp->getNameId());
        $this->assertSame('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', $resp->getNameIdFormat());
    }

    public function testSignedResponseOnlyIsAccepted() {
        $resp = $this->validate(SAMLResponseBuilder::create()->signAssertion(false)->signResponse(true));
        $this->assertTrue($resp->isVerified());
    }

    public function testResponseAndAssertionBothSignedIsAccepted() {
        $resp = $this->validate(SAMLResponseBuilder::create()->signResponse(true));
        $this->assertTrue($resp->isVerified());
    }

    public function testAttributesAreExposed() {
        $resp = $this->validate(SAMLResponseBuilder::create()->withAttributes([
            SAMLResponseBuilder::UPN => ['user@example.com'],
            'proxyAddresses' => ['SMTP:user@example.com', 'smtp:alias@example.com'],
        ]));

        $this->assertSame(['SMTP:user@example.com', 'smtp:alias@example.com'], $resp->getAttribute('proxyAddresses'));
        $this->assertSame([], $resp->getAttribute('missing'));
        $this->assertCount(2, $resp->getAttributes());
    }

    public function testUsernameFromNamedAttribute() {
        $builder = SAMLResponseBuilder::create()->withAttributes([
            'displayname' => ['Not A Username'],
            SAMLResponseBuilder::UPN => ['Named@Example.com'],
        ]);
        $validator = $this->validator();
        $validator->setUsernameAttribute(SAMLResponseBuilder::UPN);

        $this->assertSame('named@example.com', $this->validate($builder, $validator)->getUserName());
    }

    public function testUsernameDefaultsToFirstAttributeValue() {
        $builder = SAMLResponseBuilder::create()->withAttributes([
            'first' => ['First@Example.com'],
            'second' => ['second@example.com'],
        ]);
        $this->assertSame('first@example.com', $this->validate($builder)->getUserName());
    }

    public function testNotOnOrAfterIsEarliestExpiry() {
        $resp = $this->validate(SAMLResponseBuilder::create()->withSubjectConfirmationExpiry(SAMLResponseBuilder::NOW + 120));
        $this->assertSame(SAMLResponseBuilder::NOW + 120, $resp->getNotOnOrAfter());
    }

    public function testCertificateRolloverAcceptsEitherCertificate() {
        $validator = $this->validator([SAMLResponseBuilder::certificate('old'), SAMLResponseBuilder::certificate('adfs')]);
        $this->assertTrue($this->validate(SAMLResponseBuilder::create(), $validator)->isVerified());
    }

    public function testCertificateWithoutPemHeadersIsAccepted() {
        $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', SAMLResponseBuilder::certificate());
        $this->assertTrue($this->validate(SAMLResponseBuilder::create(), $this->validator($body))->isVerified());
    }

    public function testSha1AcceptedWhenAllowed() {
        $validator = $this->validator();
        $validator->setAllowSha1(true);
        $this->assertTrue($this->validate(SAMLResponseBuilder::create()->withSha1(), $validator)->isVerified());
    }

    public function testClockSkewToleratesSlightlyExpiredAssertion() {
        $builder = SAMLResponseBuilder::create()
            ->withSubjectConfirmationExpiry(SAMLResponseBuilder::NOW - 60)
            ->withConditions(SAMLResponseBuilder::NOW - 600, SAMLResponseBuilder::NOW - 60);
        $this->assertTrue($this->validate($builder)->isVerified());
    }

    public function testMatchingIssuerAndRecipientAreAccepted() {
        $validator = $this->validator();
        $validator->setIssuer(SAMLResponseBuilder::ISSUER);
        $validator->setRecipient(SAMLResponseBuilder::RECIPIENT);
        $this->assertTrue($this->validate(SAMLResponseBuilder::create(), $validator)->isVerified());
    }

    // ---- Forgery and tampering ---------------------------------------------

    public function testUnsignedResponseIsRejected() {
        $this->assertRejected(SAMLValidationException::REASON_UNSIGNED, SAMLResponseBuilder::create()->signAssertion(false));
    }

    public function testResponseSignedByAnotherKeyIsRejected() {
        $this->assertRejected(SAMLValidationException::REASON_INVALID_SIGNATURE, SAMLResponseBuilder::create()->withSigningKey('attacker'));
    }

    public function testTamperedAttributeIsRejected() {
        $builder = SAMLResponseBuilder::create()->mutate(function (DOMDocument $doc) {
            $this->xpath($doc)->query('//saml:AttributeValue')->item(0)->textContent = 'admin@example.com';
        });
        $this->assertRejected(SAMLValidationException::REASON_INVALID_SIGNATURE, $builder);
    }

    public function testTamperedSignatureValueIsRejected() {
        $builder = SAMLResponseBuilder::create()->mutate(function (DOMDocument $doc) {
            $node = $this->xpath($doc)->query('//ds:SignatureValue')->item(0);
            $node->textContent = base64_encode(str_repeat("\0", 256));
        });
        $this->assertRejected(SAMLValidationException::REASON_INVALID_SIGNATURE, $builder);
    }

    public function testInvalidResponseSignatureIsRejectedEvenIfAssertionIsValid() {
        $builder = SAMLResponseBuilder::create()->signResponse(true)->mutate(function (DOMDocument $doc) {
            $doc->documentElement->setAttribute('Destination', 'https://evil.example.com');
        });
        $this->assertRejected(SAMLValidationException::REASON_INVALID_SIGNATURE, $builder);
    }

    public function testSignatureWrappingWithSecondAssertionIsRejected() {
        // Classic XSW: keep the genuine signed assertion, add a forged one first.
        $builder = SAMLResponseBuilder::create()->mutate(function (DOMDocument $doc) {
            $xpath = $this->xpath($doc);
            $genuine = $xpath->query('//saml:Assertion')->item(0);
            $forged = $genuine->cloneNode(true);
            $forged->setAttribute('ID', '_forged');
            $sig = $xpath->query('ds:Signature', $forged)->item(0);
            $forged->removeChild($sig);
            $xpath->query('saml:AttributeStatement/saml:Attribute/saml:AttributeValue', $forged)->item(0)->textContent = 'admin@example.com';
            $doc->documentElement->insertBefore($forged, $genuine);
        });
        $this->assertRejected(SAMLValidationException::REASON_INVALID_ASSERTION_COUNT, $builder);
    }

    public function testSignatureWrappingWithGenuineAssertionHiddenIsRejected() {
        // XSW variant: move the genuine assertion inside the signature, put a
        // forged assertion with the same ID in its place.
        $builder = SAMLResponseBuilder::create()->mutate(function (DOMDocument $doc) {
            $xpath = $this->xpath($doc);
            $genuine = $xpath->query('//saml:Assertion')->item(0);
            $forged = $genuine->cloneNode(true);
            $sig = $xpath->query('ds:Signature', $genuine)->item(0);
            $xpath->query('saml:AttributeStatement/saml:Attribute/saml:AttributeValue', $forged)->item(0)->textContent = 'admin@example.com';
            $forgedSig = $xpath->query('ds:Signature', $forged)->item(0);
            $object = $doc->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Object');
            $forgedSig->appendChild($object);
            $genuine->removeChild($sig);
            $object->appendChild($genuine);
            $doc->documentElement->appendChild($forged);
        });
        $this->assertRejected(SAMLValidationException::REASON_INVALID_ASSERTION_COUNT, $builder);
    }

    public function testDuplicateIdIsRejected() {
        $builder = SAMLResponseBuilder::create()->mutate(function (DOMDocument $doc) {
            $extensions = $doc->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:Extensions');
            $extensions->setAttribute('ID', '_assertion1');
            $doc->documentElement->insertBefore($extensions, $doc->documentElement->firstChild->nextSibling);
        });
        $this->assertRejected(SAMLValidationException::REASON_DUPLICATE_ID, $builder);
    }

    public function testReferenceToAnotherElementIsRejected() {
        // The assertion carries a signature that is valid for the Response, not for itself.
        $builder = SAMLResponseBuilder::create()->signAssertion(false)->signResponse(true)->mutate(function (DOMDocument $doc) {
            $xpath = $this->xpath($doc);
            $sig = $xpath->query('/samlp:Response/ds:Signature')->item(0);
            $assertion = $xpath->query('//saml:Assertion')->item(0);
            $assertion->insertBefore($sig, $xpath->query('saml:Subject', $assertion)->item(0));
        });
        $this->assertRejected(SAMLValidationException::REASON_UNSUPPORTED_SIGNATURE, $builder);
    }

    public function testEmbeddedCertificateIsIgnored() {
        // Signed with the attacker's key and carrying the attacker's certificate.
        $this->assertRejected(SAMLValidationException::REASON_INVALID_SIGNATURE, SAMLResponseBuilder::create()->withSigningKey('attacker'));
    }

    public function testSha1RejectedByDefault() {
        $this->assertRejected(SAMLValidationException::REASON_UNSUPPORTED_SIGNATURE, SAMLResponseBuilder::create()->withSha1());
    }

    public function testHmacSignatureMethodIsRejected() {
        $builder = SAMLResponseBuilder::create()->mutate(function (DOMDocument $doc) {
            $this->xpath($doc)->query('//ds:SignatureMethod')->item(0)
                ->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#hmac-sha1');
        });
        $this->assertRejected(SAMLValidationException::REASON_UNSUPPORTED_SIGNATURE, $builder);
    }

    public function testXPathTransformIsRejected() {
        $builder = SAMLResponseBuilder::create()->mutate(function (DOMDocument $doc) {
            $this->xpath($doc)->query('//ds:Transform')->item(1)
                ->setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xpath-19991116');
        });
        $this->assertRejected(SAMLValidationException::REASON_UNSUPPORTED_SIGNATURE, $builder);
    }

    public function testSha1DigestUnderSha256SignatureIsRejected() {
        $builder = SAMLResponseBuilder::create()->withDigestAlgorithm('http://www.w3.org/2000/09/xmldsig#sha1');
        $this->assertRejected(SAMLValidationException::REASON_UNSUPPORTED_SIGNATURE, $builder);
    }

    public function testUnknownCanonicalizationIsRejected() {
        $builder = SAMLResponseBuilder::create()->mutate(function (DOMDocument $doc) {
            $this->xpath($doc)->query('//ds:CanonicalizationMethod')->item(0)
                ->setAttribute('Algorithm', 'http://www.w3.org/2006/12/xml-c14n11');
        });
        $this->assertRejected(SAMLValidationException::REASON_UNSUPPORTED_SIGNATURE, $builder);
    }

    public function testSecondReferenceIsRejected() {
        $builder = SAMLResponseBuilder::create()->mutate(function (DOMDocument $doc) {
            $reference = $this->xpath($doc)->query('//ds:Reference')->item(0);
            $reference->parentNode->appendChild($reference->cloneNode(true));
        });
        $this->assertRejected(SAMLValidationException::REASON_UNSUPPORTED_SIGNATURE, $builder);
    }

    public function testSecondSignatureOnSameElementIsRejected() {
        $builder = SAMLResponseBuilder::create()->mutate(function (DOMDocument $doc) {
            $signature = $this->xpath($doc)->query('//ds:Signature')->item(0);
            $signature->parentNode->insertBefore($signature->cloneNode(true), $signature);
        });
        $this->assertRejected(SAMLValidationException::REASON_UNSUPPORTED_SIGNATURE, $builder);
    }

    public function testTooManyTransformsIsRejected() {
        $builder = SAMLResponseBuilder::create()->mutate(function (DOMDocument $doc) {
            $transform = $this->xpath($doc)->query('//ds:Transform')->item(1);
            $transform->parentNode->appendChild($transform->cloneNode(true));
        });
        $this->assertRejected(SAMLValidationException::REASON_UNSUPPORTED_SIGNATURE, $builder);
    }

    public function testEncryptedAssertionIsRejected() {
        $builder = SAMLResponseBuilder::create()->mutate(function (DOMDocument $doc) {
            $encrypted = $doc->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'EncryptedAssertion');
            $doc->documentElement->appendChild($encrypted);
        });
        $this->assertRejected(SAMLValidationException::REASON_ENCRYPTED_ASSERTION, $builder);
    }

    public function testFailureStatusIsRejected() {
        $this->assertRejected(
            SAMLValidationException::REASON_STATUS_NOT_SUCCESS,
            SAMLResponseBuilder::create()->withStatus('urn:oasis:names:tc:SAML:2.0:status:Requester')
        );
    }

    // ---- Conditions and subject confirmation -------------------------------

    public function testWrongAudienceIsRejected() {
        // An assertion ADFS issued to another relying party.
        $this->assertRejected(SAMLValidationException::REASON_AUDIENCE_MISMATCH, SAMLResponseBuilder::create()->withAudience('https://other-app.example.com'));
    }

    public function testMissingAudienceRestrictionIsRejected() {
        // An assertion with no audience at all must not be accepted by every application.
        $builder = SAMLResponseBuilder::create()->withAudienceRestrictions([]);
        $this->assertRejected(SAMLValidationException::REASON_AUDIENCE_MISMATCH, $builder);
    }

    public function testEveryAudienceRestrictionMustIncludeAudience() {
        // Restrictions are ANDed: the second one excludes this application.
        $builder = SAMLResponseBuilder::create()->withAudienceRestrictions([
            [SAMLResponseBuilder::AUDIENCE],
            ['https://other-app.example.com'],
        ]);
        $this->assertRejected(SAMLValidationException::REASON_AUDIENCE_MISMATCH, $builder);
    }

    public function testAudienceAmongSeveralIsAccepted() {
        $builder = SAMLResponseBuilder::create()->withAudienceRestrictions([
            ['https://other-app.example.com', SAMLResponseBuilder::AUDIENCE],
        ]);
        $this->assertTrue($this->validate($builder)->isVerified());
    }

    public function testMissingConditionsIsRejected() {
        $this->assertRejected(SAMLValidationException::REASON_AUDIENCE_MISMATCH, SAMLResponseBuilder::create()->withoutConditions());
    }

    public function testHolderOfKeyConfirmationIsNotTreatedAsBearer() {
        $builder = SAMLResponseBuilder::create()->withConfirmationMethod('urn:oasis:names:tc:SAML:2.0:cm:holder-of-key');
        $this->assertRejected(SAMLValidationException::REASON_INVALID_SUBJECT_CONFIRMATION, $builder);
    }

    public function testSubjectConfirmationWithoutExpiryIsRejected() {
        $builder = SAMLResponseBuilder::create()->withSubjectConfirmationExpiry(null);
        $this->assertRejected(SAMLValidationException::REASON_INVALID_SUBJECT_CONFIRMATION, $builder);
    }

    public function testExpiredConditionsAreRejected() {
        $builder = SAMLResponseBuilder::create()->withConditions(SAMLResponseBuilder::NOW - 7200, SAMLResponseBuilder::NOW - 3600);
        $this->assertRejected(SAMLValidationException::REASON_EXPIRED, $builder);
    }

    public function testNotYetValidIsRejected() {
        $builder = SAMLResponseBuilder::create()->withConditions(SAMLResponseBuilder::NOW + 3600, SAMLResponseBuilder::NOW + 7200);
        $this->assertRejected(SAMLValidationException::REASON_NOT_YET_VALID, $builder);
    }

    public function testExpiredSubjectConfirmationIsRejected() {
        $builder = SAMLResponseBuilder::create()->withSubjectConfirmationExpiry(SAMLResponseBuilder::NOW - 600);
        $this->assertRejected(SAMLValidationException::REASON_EXPIRED, $builder);
    }

    public function testZeroClockSkewIsStrict() {
        $validator = $this->validator();
        $validator->setClockSkew(0);
        $builder = SAMLResponseBuilder::create()->withSubjectConfirmationExpiry(SAMLResponseBuilder::NOW);
        $this->assertRejected(SAMLValidationException::REASON_EXPIRED, $builder, $validator);
    }

    public function testWrongIssuerIsRejected() {
        $validator = $this->validator();
        $validator->setIssuer(SAMLResponseBuilder::ISSUER);
        $this->assertRejected(SAMLValidationException::REASON_ISSUER_MISMATCH, SAMLResponseBuilder::create()->withIssuer('http://evil.example.com/adfs/services/trust'), $validator);
    }

    public function testWrongRecipientIsRejected() {
        $validator = $this->validator();
        $validator->setRecipient(SAMLResponseBuilder::RECIPIENT);
        $this->assertRejected(SAMLValidationException::REASON_RECIPIENT_MISMATCH, SAMLResponseBuilder::create()->withRecipient('https://other-app.example.com/verify'), $validator);
    }

    public function testInResponseToMismatchIsRejected() {
        $builder = SAMLResponseBuilder::create()->withInResponseTo('Other_App', 'My_App');
        $this->assertRejected(SAMLValidationException::REASON_IN_RESPONSE_TO_MISMATCH, $builder);
    }

    public function testUnsignedResponseInResponseToIsNotTrusted() {
        // Only the assertion is signed, and it has no InResponseTo: the
        // Response-level value could be forged, so it is not used.
        $resp = $this->validate(SAMLResponseBuilder::create()->withInResponseTo('Some_App', ''));
        $this->assertSame('', $resp->getAppName());
    }

    public function testSignedResponseInResponseToIsTrusted() {
        $resp = $this->validate(SAMLResponseBuilder::create()->signResponse(true)->withInResponseTo('Some_App', ''));
        $this->assertSame('Some App', $resp->getAppName());
    }

    public function testMissingUsernameIsRejected() {
        $this->assertRejected(SAMLValidationException::REASON_MISSING_USERNAME, SAMLResponseBuilder::create()->withAttributes([]));
    }

    public function testMissingNamedUsernameAttributeIsRejected() {
        $validator = $this->validator();
        $validator->setUsernameAttribute('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress');
        $this->assertRejected(SAMLValidationException::REASON_MISSING_USERNAME, SAMLResponseBuilder::create(), $validator);
    }

    public function testFailedValidationLeavesResponseUnverified() {
        $resp = new ADFSResponse(SAMLResponseBuilder::create()->withSigningKey('attacker')->encoded());

        try {
            $this->validator()->validate($resp);
        } catch (SAMLValidationException $e) {
        }
        $this->assertFalse($resp->isVerified());
        $this->assertNull($resp->getAssertionId());
    }

    // ---- Configuration -----------------------------------------------------

    public function testNoCertificateIsRejected() {
        $this->expectException(InvalidArgumentException::class);
        new ADFSResponseValidator([], SAMLResponseBuilder::AUDIENCE);
    }

    public function testInvalidCertificateIsRejected() {
        $this->expectException(InvalidArgumentException::class);
        new ADFSResponseValidator('not a certificate', SAMLResponseBuilder::AUDIENCE);
    }

    public function testEmptyAudienceIsRejected() {
        $this->expectException(InvalidArgumentException::class);
        new ADFSResponseValidator(SAMLResponseBuilder::certificate(), ' ');
    }

    public function testClockSkewOutOfRangeIsRejected() {
        $this->expectException(InvalidArgumentException::class);
        $this->validator()->setClockSkew(3600);
    }

    public function testGetters() {
        $validator = $this->validator();
        $validator->setIssuer(' '.SAMLResponseBuilder::ISSUER.' ');
        $validator->setRecipient('');
        $validator->setUsernameAttribute(SAMLResponseBuilder::UPN);

        $this->assertSame(SAMLResponseBuilder::AUDIENCE, $validator->getAudience());
        $this->assertSame(ADFSResponseValidator::DEFAULT_CLOCK_SKEW, $validator->getClockSkew());
        $this->assertSame(SAMLResponseBuilder::ISSUER, $validator->getIssuer());
        $this->assertNull($validator->getRecipient());
        $this->assertSame(SAMLResponseBuilder::UPN, $validator->getUsernameAttribute());
    }

    // ---- Helpers -----------------------------------------------------------

    private function assertRejected(string $reason, SAMLResponseBuilder $builder, ?ADFSResponseValidator $validator = null): void {
        $resp = new ADFSResponse($builder->encoded());

        try {
            ($validator ?? $this->validator())->validate($resp);
            $this->fail('Expected SAMLValidationException with reason '.$reason);
        } catch (SAMLValidationException $e) {
            $this->assertSame($reason, $e->getReason(), $e->getMessage());
        }
    }

    private function validate(SAMLResponseBuilder $builder, ?ADFSResponseValidator $validator = null): ADFSResponse {
        $resp = new ADFSResponse($builder->encoded());
        ($validator ?? $this->validator())->validate($resp);

        return $resp;
    }

    private function validator(string|array|null $certificates = null): ADFSResponseValidator {
        $validator = new ADFSResponseValidator($certificates ?? SAMLResponseBuilder::certificate(), SAMLResponseBuilder::AUDIENCE);
        $validator->setCurrentTime(SAMLResponseBuilder::NOW);

        return $validator;
    }

    private function xpath(DOMDocument $doc): DOMXPath {
        return ADFSResponse::createXPath($doc);
    }
}
