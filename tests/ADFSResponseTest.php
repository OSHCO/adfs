<?php
namespace Tests;

use Oshco\Adfs\ADFSResponse;
use Oshco\Adfs\SAMLValidationException;
use PHPUnit\Framework\TestCase;

/**
 * Parsing behavior of ADFSResponse, before any validation.
 */
class ADFSResponseTest extends TestCase {

    public function testSuccessResponse() {
        $resp = new ADFSResponse(SAMLResponseBuilder::create()->encoded());
        $this->assertTrue($resp->isSuccess());
        $this->assertSame(ADFSResponse::STATUS_SUCCESS, $resp->getStatusCode());
    }

    public function testFailureResponse() {
        $resp = new ADFSResponse(SAMLResponseBuilder::create()->withStatus('urn:oasis:names:tc:SAML:2.0:status:Requester')->encoded());
        $this->assertFalse($resp->isSuccess());
        $this->assertSame('urn:oasis:names:tc:SAML:2.0:status:Requester', $resp->getStatusCode());
    }

    public function testNewResponseIsNotVerified() {
        $resp = new ADFSResponse(SAMLResponseBuilder::create()->encoded());
        $this->assertFalse($resp->isVerified());
        $this->assertNull($resp->getAssertionId());
        $this->assertNull($resp->getNameId());
        $this->assertSame([], $resp->getAttributes());
    }

    public function testUnverifiedUserNameIsLowerCased() {
        $resp = new ADFSResponse(SAMLResponseBuilder::create()->withUsername('TestUser@Example.COM')->encoded());
        $this->assertSame('testuser@example.com', $resp->getUserName());
    }

    public function testUnverifiedUserNameIsEmptyWithoutAttributes() {
        $resp = new ADFSResponse(SAMLResponseBuilder::create()->withAttributes([])->encoded());
        $this->assertSame('', $resp->getUserName());
    }

    public function testGetAppNameReplacesUnderscores() {
        $resp = new ADFSResponse(SAMLResponseBuilder::create()->withAppId('My_Test_App')->encoded());
        $this->assertSame('My Test App', $resp->getAppName());
    }

    public function testGetAppNameNoUnderscores() {
        $resp = new ADFSResponse(SAMLResponseBuilder::create()->withAppId('SimpleApp')->encoded());
        $this->assertSame('SimpleApp', $resp->getAppName());
    }

    public function testGetXMLStringAddsDeclaration() {
        $resp = new ADFSResponse(SAMLResponseBuilder::encode(SAMLResponseBuilder::create()->unsignedXml()));
        $this->assertStringStartsWith('<?xml', $resp->getXMLString());
        $this->assertStringContainsString('samlp:Response', $resp->getXMLString());
    }

    public function testGetRawXMLIsUnchanged() {
        $xml = SAMLResponseBuilder::create()->build();
        $resp = new ADFSResponse(base64_encode($xml));
        $this->assertSame($xml, $resp->getRawXML());
    }

    public function testToJSONContainsExpectedKeys() {
        $resp = new ADFSResponse(SAMLResponseBuilder::create()->withAppId('My_App')->encoded());
        $decoded = json_decode((string) $resp, true);
        $this->assertSame('My App', $decoded['appName']);
        $this->assertTrue($decoded['isSuccess']);
        $this->assertFalse($decoded['isVerified']);
        $this->assertSame('user@example.com', $decoded['username']);
    }

    public function testFailureResponseWithoutAssertionParses() {
        $resp = new ADFSResponse(SAMLResponseBuilder::create()->withStatus('urn:oasis:names:tc:SAML:2.0:status:Responder')->encoded());
        $this->assertFalse($resp->isSuccess());
        $this->assertSame('', $resp->getUserName());
    }

    public function testInvalidBase64IsRejected() {
        $this->assertRejected(SAMLValidationException::REASON_MALFORMED, 'not base64 !!');
    }

    public function testEmptyInputIsRejected() {
        $this->assertRejected(SAMLValidationException::REASON_MALFORMED, '');
    }

    public function testNonXmlIsRejected() {
        $this->assertRejected(SAMLValidationException::REASON_MALFORMED, base64_encode('this is not xml'));
    }

    public function testWrongRootElementIsRejected() {
        $this->assertRejected(SAMLValidationException::REASON_MALFORMED, base64_encode('<Response xmlns="urn:example"><Status/></Response>'));
    }

    public function testDoctypeIsRejected() {
        $xml = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            .'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&x;</samlp:Response>';
        $this->assertRejected(SAMLValidationException::REASON_DOCTYPE_NOT_ALLOWED, base64_encode($xml));
    }

    public function testOversizedResponseIsRejected() {
        $xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            .str_repeat(' ', ADFSResponse::MAX_SIZE).'</samlp:Response>';
        $this->assertRejected(SAMLValidationException::REASON_MALFORMED, base64_encode($xml));
    }

    private function assertRejected(string $reason, string $encoded): void {
        try {
            new ADFSResponse($encoded);
            $this->fail('Expected SAMLValidationException with reason '.$reason);
        } catch (SAMLValidationException $e) {
            $this->assertSame($reason, $e->getReason());
        }
    }
}
