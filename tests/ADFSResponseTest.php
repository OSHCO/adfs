<?php
namespace Tests;

use Exception;
use Oshco\Adfs\ADFSResponse;
use PHPUnit\Framework\TestCase;

class ADFSResponseTest extends TestCase {

    public function testSuccessResponse() {
        $resp = new ADFSResponse(SAMLResponseBuilder::buildSuccess());
        $this->assertTrue($resp->isSuccess());
    }

    public function testFailureResponse() {
        $resp = new ADFSResponse(SAMLResponseBuilder::buildFailure());
        $this->assertFalse($resp->isSuccess());
    }

    public function testGetUserNameIsLowerCased() {
        $resp = new ADFSResponse(SAMLResponseBuilder::buildSuccess('TestUser@Example.COM'));
        $this->assertSame('testuser@example.com', $resp->getUserName());
    }

    public function testGetAppNameReplacesUnderscores() {
        $resp = new ADFSResponse(SAMLResponseBuilder::buildSuccess('user@example.com', 'My_Test_App'));
        $this->assertSame('My Test App', $resp->getAppName());
    }

    public function testGetAppNameNoUnderscores() {
        $resp = new ADFSResponse(SAMLResponseBuilder::buildSuccess('user@example.com', 'SimpleApp'));
        $this->assertSame('SimpleApp', $resp->getAppName());
    }

    public function testGetXMLStringReturnsNonEmpty() {
        $resp = new ADFSResponse(SAMLResponseBuilder::buildSuccess());
        $this->assertNotEmpty($resp->getXMLString());
        $this->assertStringContainsString('saml2p:Response', $resp->getXMLString());
    }

    public function testToStringReturnsJSON() {
        $resp = new ADFSResponse(SAMLResponseBuilder::buildSuccess('user@example.com', 'My_App'));
        $str = (string) $resp;
        $decoded = json_decode($str, true);
        $this->assertNotNull($decoded);
        $this->assertSame('My App', $decoded['appName']);
        $this->assertTrue($decoded['isSuccess']);
        $this->assertSame('user@example.com', $decoded['username']);
    }

    public function testToJSONContainsExpectedKeys() {
        $resp = new ADFSResponse(SAMLResponseBuilder::buildSuccess());
        $json = $resp->toJSON();
        $str = $json . '';
        $decoded = json_decode($str, true);
        $this->assertArrayHasKey('appName', $decoded);
        $this->assertArrayHasKey('isSuccess', $decoded);
        $this->assertArrayHasKey('username', $decoded);
    }

    public function testMissingUsernameThrowsException() {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("The attribute 'username' is missing from SAML response");
        new ADFSResponse(SAMLResponseBuilder::buildWithoutUsername());
    }

    public function testFailureResponseStillParsesUsername() {
        $resp = new ADFSResponse(SAMLResponseBuilder::buildFailure('admin@example.com'));
        $this->assertFalse($resp->isSuccess());
        $this->assertSame('admin@example.com', $resp->getUserName());
    }
}
