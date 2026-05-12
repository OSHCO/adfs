<?php
namespace Tests;

use Oshco\Adfs\SAMLRequest;
use PHPUnit\Framework\TestCase;

class SAMLRequestTest extends TestCase {

    public function testDefaultValues() {
        $req = new SAMLRequest();
        $this->assertSame('', $req->getAppID());
        $this->assertSame('', $req->getAppUrl());
        $this->assertSame('', $req->getDestination());
        $this->assertSame('', $req->getIssueInstance());
    }

    public function testSetAndGetDestination() {
        $req = new SAMLRequest();
        $req->setDestination('https://adfs.example.com/adfs/ls');
        $this->assertSame('https://adfs.example.com/adfs/ls', $req->getDestination());
    }

    public function testSetAndGetAppID() {
        $req = new SAMLRequest();
        $req->setAppID('My Application');
        $this->assertSame('My_Application', $req->getAppID());
    }

    public function testSetAppIDNoSpaces() {
        $req = new SAMLRequest();
        $req->setAppID('TestApp');
        $this->assertSame('TestApp', $req->getAppID());
    }

    public function testSetAndGetAppURL() {
        $req = new SAMLRequest();
        $req->setAppURL('https://myapp.example.com');
        $this->assertSame('https://myapp.example.com', $req->getAppUrl());
    }

    public function testSetAndGetIssueInstant() {
        $req = new SAMLRequest();
        $req->setIssueInstant('2026-01-01T00:00:00Z');
        $this->assertSame('2026-01-01T00:00:00Z', $req->getIssueInstance());
    }

    public function testToStringProducesValidXML() {
        $req = new SAMLRequest();
        $req->setDestination('https://adfs.example.com/adfs/ls');
        $req->setAppID('Test App');
        $req->setAppURL('https://myapp.example.com');
        $req->setIssueInstant('2026-01-01T00:00:00Z');

        $xml = (string) $req;

        $this->assertStringContainsString('saml2p:AuthnRequest', $xml);
        $this->assertStringContainsString('Destination="https://adfs.example.com/adfs/ls"', $xml);
        $this->assertStringContainsString('ID="Test_App"', $xml);
        $this->assertStringContainsString('IssueInstant="2026-01-01T00:00:00Z"', $xml);
        $this->assertStringContainsString('Version="2.0"', $xml);
        $this->assertStringContainsString('ForceAuthn="false"', $xml);
        $this->assertStringContainsString('ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', $xml);
        $this->assertStringContainsString('saml2:Issuer', $xml);
        $this->assertStringContainsString('https://myapp.example.com', $xml);
        $this->assertStringContainsString('saml2p:NameIDPolicy', $xml);
        $this->assertStringContainsString('AllowCreate="true"', $xml);
    }

    public function testEncodeReturnsBase64String() {
        $req = new SAMLRequest();
        $req->setDestination('https://adfs.example.com/adfs/ls');
        $req->setAppID('TestApp');
        $req->setAppURL('https://myapp.example.com');
        $req->setIssueInstant('2026-01-01T00:00:00Z');

        $encoded = $req->encode();

        // Must be valid base64
        $this->assertNotFalse(base64_decode($encoded, true));

        // Decoding and inflating should give back the XML
        $decoded = gzinflate(base64_decode($encoded));
        $this->assertStringContainsString('saml2p:AuthnRequest', $decoded);
        $this->assertStringContainsString('TestApp', $decoded);
    }
}
