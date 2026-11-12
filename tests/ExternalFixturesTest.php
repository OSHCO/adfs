<?php
namespace Tests;

use DOMDocument;
use Oshco\Adfs\ADFSResponse;
use Oshco\Adfs\ADFSResponseValidator;
use Oshco\Adfs\SAMLValidationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Validates ADFS responses signed by another implementation (ruby-saml
 * fixtures), so the tests do not only check xmlseclibs against itself.
 * See tests/fixtures/ruby-saml/README.md.
 */
class ExternalFixturesTest extends TestCase {
    private const AUDIENCE = 'example.com';
    private const NOW = '2011-06-22T12:50:00Z';

    public static function fixtures(): array {
        return [
            'sha256' => ['adfs_response_sha256.xml'],
            'sha512' => ['adfs_response_sha512.xml'],
            'xmlns' => ['adfs_response_xmlns.xml'],
        ];
    }

    #[DataProvider('fixtures')]
    public function testUntouchedPassesAllSignatureAndConditionChecks(string $file) {
        // The fixtures carry no attributes, so the last check is the only one that fails.
        $this->assertReason(SAMLValidationException::REASON_MISSING_USERNAME, $this->load($file));
    }

    #[DataProvider('fixtures')]
    public function testTamperedNameIdIsRejected(string $file) {
        $xml = preg_replace('#(<NameID[^>]*>)[^<]+#', '$1admin@example.com', $this->load($file), 1);
        $this->assertReason(SAMLValidationException::REASON_INVALID_SIGNATURE, $xml);
    }

    #[DataProvider('fixtures')]
    public function testWrongAudienceIsRejected(string $file) {
        $this->assertReason(SAMLValidationException::REASON_AUDIENCE_MISMATCH, $this->load($file), 'other.example.com');
    }

    #[DataProvider('fixtures')]
    public function testExpiredIsRejected(string $file) {
        $this->assertReason(SAMLValidationException::REASON_EXPIRED, $this->load($file), self::AUDIENCE, strtotime('2011-06-22T14:00:00Z'));
    }

    #[DataProvider('fixtures')]
    public function testOtherCertificateIsRejected(string $file) {
        $resp = new ADFSResponse(base64_encode($this->load($file)));
        $validator = new ADFSResponseValidator(SAMLResponseBuilder::certificate(), self::AUDIENCE);
        $validator->setCurrentTime(strtotime(self::NOW));

        try {
            $validator->validate($resp);
            $this->fail('Expected rejection');
        } catch (SAMLValidationException $e) {
            $this->assertSame(SAMLValidationException::REASON_INVALID_SIGNATURE, $e->getReason());
        }
    }

    private function assertReason(string $reason, string $xml, string $audience = self::AUDIENCE, ?int $now = null): void {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        // Fixture quirk: the element holds base64 of a PEM file.
        $certificate = base64_decode($doc->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509Certificate')->item(0)->textContent);

        $validator = new ADFSResponseValidator($certificate, $audience);
        $validator->setCurrentTime($now ?? strtotime(self::NOW));
        $validator->setIssuer('http://login.example.com/issuer');
        $validator->setRecipient('https://someone.example.com/endpoint');

        try {
            $validator->validate(new ADFSResponse(base64_encode($xml)));
            $this->fail('Expected SAMLValidationException with reason '.$reason);
        } catch (SAMLValidationException $e) {
            $this->assertSame($reason, $e->getReason(), $e->getMessage());
        }
    }

    private function load(string $file): string {
        return file_get_contents(__DIR__.'/fixtures/ruby-saml/'.$file);
    }
}
