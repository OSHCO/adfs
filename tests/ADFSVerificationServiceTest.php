<?php
namespace Tests;

use Oshco\Adfs\ADFSResponse;
use Oshco\Adfs\ADFSResponseValidator;
use Oshco\Adfs\ADFSUser;
use Oshco\Adfs\ADFSVerificationService;
use Oshco\Adfs\SAMLValidationException;
use PHPUnit\Framework\TestCase;
use WebFiori\Http\WebServicesManager;

/**
 * A concrete test implementation of ADFSVerificationService.
 */
class TestVerificationService extends ADFSVerificationService {
    private $mockUser;
    private $successCalled = false;
    private $failCalled = false;
    private $lastUser;
    private ?string $requestedUsername = null;
    private bool $replayed = false;

    public function __construct(string $name = 'test-verify', string $failRedirect = 'https://example.com/fail') {
        parent::__construct($name, $failRedirect);
    }

    public function setMockUser(?ADFSUser $user) {
        $this->mockUser = $user;
    }

    public function setReplayed(bool $replayed) {
        $this->replayed = $replayed;
    }

    public function getRequestedUsername(): ?string {
        return $this->requestedUsername;
    }

    public function getUser(string $username): ?ADFSUser {
        $this->requestedUsername = $username;

        return $this->mockUser;
    }

    public function getValidator(): ADFSResponseValidator {
        return testValidator();
    }

    public function isAssertionReplayed(ADFSResponse $response): bool {
        return $this->replayed;
    }

    public function onSuccess(ADFSUser $user) {
        $this->successCalled = true;
        $this->lastUser = $user;
    }

    public function onFail(?ADFSUser $user = null) {
        $this->failCalled = true;
        $this->lastUser = $user;
    }

    public function wasSuccessCalled(): bool {
        return $this->successCalled;
    }

    public function wasFailCalled(): bool {
        return $this->failCalled;
    }

    public function getLastUser(): ?ADFSUser {
        return $this->lastUser;
    }

    public function resetFlags() {
        $this->successCalled = false;
        $this->failCalled = false;
        $this->lastUser = null;
    }
}

/**
 * A concrete subclass that uses the real onFail implementation.
 * Only overrides onSuccess since it's abstract.
 */
class RealFailVerificationService extends ADFSVerificationService {
    private $mockUser;

    public function __construct(string $name = 'real-verify', string $failRedirect = 'https://example.com/fail') {
        parent::__construct($name, $failRedirect);
    }

    public function setMockUser(?ADFSUser $user) {
        $this->mockUser = $user;
    }

    public function getUser(string $username): ?ADFSUser {
        return $this->mockUser;
    }

    public function getValidator(): ADFSResponseValidator {
        return testValidator();
    }

    public function onSuccess(ADFSUser $user) {
    }
}

function testValidator(): ADFSResponseValidator {
    $validator = new ADFSResponseValidator(SAMLResponseBuilder::certificate(), SAMLResponseBuilder::AUDIENCE);
    $validator->setCurrentTime(SAMLResponseBuilder::NOW);

    return $validator;
}

class TestUser implements ADFSUser {
    private $id;

    public function __construct($id = 1) {
        $this->id = $id;
    }

    public function getId() {
        return $this->id;
    }
}

class ADFSVerificationServiceTest extends TestCase {

    public function testConstructorSetsName() {
        $svc = new TestVerificationService('my-verify');
        $this->assertSame('my-verify', $svc->getName());
    }

    public function testConstructorSetsFailRedirect() {
        $svc = new TestVerificationService('verify', 'https://example.com/login');
        $this->assertSame('https://example.com/login', $svc->getOnFailRedirect());
    }

    public function testDefaultName() {
        $svc = new TestVerificationService();
        $this->assertSame('test-verify', $svc->getName());
    }

    public function testAcceptsPostAndGetMethods() {
        $svc = new TestVerificationService();
        $methods = $svc->getRequestMethods();
        $this->assertContains('POST', $methods);
        $this->assertContains('GET', $methods);
    }

    public function testHasSAMLResponseParameter() {
        $svc = new TestVerificationService();
        $this->assertTrue($svc->hasParameter('SAMLResponse'));
    }

    public function testSetAndGetFailStatus() {
        $svc = new TestVerificationService();
        $this->assertSame('', $svc->getFailStatus());
        $svc->setFailStatus('USER_NOT_FOUND');
        $this->assertSame('USER_NOT_FOUND', $svc->getFailStatus());
    }

    public function testSetAndGetOnFailRedirect() {
        $svc = new TestVerificationService();
        $svc->setOnFailRedirect('https://other.example.com/error');
        $this->assertSame('https://other.example.com/error', $svc->getOnFailRedirect());
    }

    public function testGetAppNameReturnsEmptyWhenNoResponse() {
        $svc = new TestVerificationService();
        $this->assertSame('', $svc->getAppName());
    }

    public function testGetSamlResponseReturnsNullBeforeProcessing() {
        $svc = new TestVerificationService();
        $this->assertNull($svc->getSamlResponse());
    }

    public function testProcessRequestCallsOnSuccessWhenUserFound() {
        $svc = new TestVerificationService();
        $svc->setMockUser(new TestUser(42));

        $_POST['SAMLResponse'] = SAMLResponseBuilder::create()->withUsername('TestUser@example.com')->withAppId('TestApp')->encoded();
        $svc->processRequest();

        $this->assertTrue($svc->wasSuccessCalled());
        $this->assertFalse($svc->wasFailCalled());
        $this->assertSame(42, $svc->getLastUser()->getId());
        $this->assertSame('testuser@example.com', $svc->getRequestedUsername());
        $this->assertSame('TestApp', $svc->getAppName());
        $this->assertNull($svc->getError());
        $this->assertTrue($svc->getSamlResponse()->isVerified());
    }

    public function testProcessRequestCallsOnFailWhenUserNotFound() {
        $svc = new TestVerificationService();
        $svc->setMockUser(null);

        $_POST['SAMLResponse'] = SAMLResponseBuilder::create()->withUsername('unknown@example.com')->encoded();
        $svc->processRequest();

        $this->assertTrue($svc->wasFailCalled());
        $this->assertFalse($svc->wasSuccessCalled());
        $this->assertSame(ADFSVerificationService::ERROR_USER_NOT_FOUND, $svc->getError());
    }

    public function testProcessRequestCallsOnFailWhenSAMLFails() {
        $svc = new TestVerificationService();
        $svc->setMockUser(new TestUser(1));

        $_POST['SAMLResponse'] = SAMLResponseBuilder::create()->withStatus('urn:oasis:names:tc:SAML:2.0:status:Requester')->encoded();
        $svc->processRequest();

        $this->assertTrue($svc->wasFailCalled());
        $this->assertFalse($svc->wasSuccessCalled());
        $this->assertSame(SAMLValidationException::REASON_STATUS_NOT_SUCCESS, $svc->getError());
        $this->assertNull($svc->getRequestedUsername());
    }

    public function testForgedUnsignedResponseDoesNotSignIn() {
        // Regression test: version 2 accepted any well-formed XML.
        $svc = new TestVerificationService();
        $svc->setMockUser(new TestUser(1));

        $_POST['SAMLResponse'] = SAMLResponseBuilder::encode(SAMLResponseBuilder::create()->withUsername('admin@example.com')->unsignedXml());
        $svc->processRequest();

        $this->assertFalse($svc->wasSuccessCalled());
        $this->assertTrue($svc->wasFailCalled());
        $this->assertSame(SAMLValidationException::REASON_UNSIGNED, $svc->getError());
        $this->assertNull($svc->getRequestedUsername(), 'getUser() must not be called for an unverified response');
        $this->assertSame('', $svc->getAppName());
        $this->assertFalse($svc->getSamlResponse()->isVerified());
    }

    public function testResponseSignedByAnotherKeyDoesNotSignIn() {
        $svc = new TestVerificationService();
        $svc->setMockUser(new TestUser(1));

        $_POST['SAMLResponse'] = SAMLResponseBuilder::create()->withSigningKey('attacker')->encoded();
        $svc->processRequest();

        $this->assertFalse($svc->wasSuccessCalled());
        $this->assertSame(SAMLValidationException::REASON_INVALID_SIGNATURE, $svc->getError());
        $this->assertNotEmpty($svc->getErrorMessage());
    }

    public function testMalformedResponseCallsOnFail() {
        $svc = new TestVerificationService();
        $svc->setMockUser(new TestUser(1));

        $_POST['SAMLResponse'] = base64_encode('<not-saml/>');
        $svc->processRequest();

        $this->assertTrue($svc->wasFailCalled());
        $this->assertSame(SAMLValidationException::REASON_MALFORMED, $svc->getError());
        $this->assertNull($svc->getSamlResponse());
    }

    public function testReplayedAssertionCallsOnFail() {
        $svc = new TestVerificationService();
        $svc->setMockUser(new TestUser(1));
        $svc->setReplayed(true);

        $_POST['SAMLResponse'] = SAMLResponseBuilder::create()->encoded();
        $svc->processRequest();

        $this->assertFalse($svc->wasSuccessCalled());
        $this->assertSame(SAMLValidationException::REASON_REPLAYED, $svc->getError());
    }

    public function testMissingResponseDoesNotCallHandlers() {
        $svc = new TestVerificationService();
        $mgr = new WebServicesManager();
        $mgr->addService($svc);
        $svc->processRequest();

        $this->assertFalse($svc->wasSuccessCalled());
        $this->assertFalse($svc->wasFailCalled());
        $this->assertSame(ADFSVerificationService::ERROR_MISSING_RESPONSE, $svc->getError());
        $this->assertSame(400, $mgr->getResponse()->getCode());
    }

    public function testResponseInQueryStringIsIgnored() {
        $svc = new TestVerificationService();
        $svc->setMockUser(new TestUser(1));
        $_GET['SAMLResponse'] = SAMLResponseBuilder::create()->encoded();
        $svc->processRequest();

        $this->assertFalse($svc->wasSuccessCalled());
        $this->assertSame(ADFSVerificationService::ERROR_MISSING_RESPONSE, $svc->getError());
    }

    public function testErrorIsResetBetweenRequests() {
        $svc = new TestVerificationService();
        $svc->setMockUser(new TestUser(1));

        $_POST['SAMLResponse'] = SAMLResponseBuilder::create()->withSigningKey('attacker')->encoded();
        $svc->processRequest();
        $this->assertNotNull($svc->getError());

        $_POST['SAMLResponse'] = SAMLResponseBuilder::create()->encoded();
        $svc->processRequest();
        $this->assertNull($svc->getError());
        $this->assertNull($svc->getErrorMessage());
    }

    protected function tearDown(): void {
        unset($_POST['SAMLResponse'], $_GET['SAMLResponse']);
    }

    private function createRealFailService(string $failRedirect = 'https://example.com/fail'): RealFailVerificationService {
        $svc = new RealFailVerificationService('real-verify', $failRedirect);
        $mgr = new WebServicesManager();
        $mgr->addService($svc);
        return $svc;
    }

    public function testOnFailSetsResponseCode401() {
        $svc = $this->createRealFailService();
        $svc->onFail();
        $this->assertSame(401, $svc->getManager()->getResponse()->getCode());
    }

    public function testOnFailSetsLocationHeaderWithRedirectUrl() {
        $svc = $this->createRealFailService('https://myapp.example.com/login');
        $svc->onFail();
        $headers = $svc->getManager()->getResponse()->getHeaders();
        $found = false;
        foreach ($headers as $h) {
            $str = $h . '';
            if (str_contains($str, 'https://myapp.example.com/login')) {
                $found = true;
                break;
            }
        }
        $this->assertTrue($found, 'Location header should contain the fail redirect URL');
    }

    public function testOnFailAppendsStatusToRedirectUrl() {
        $svc = $this->createRealFailService('https://example.com/error');
        $svc->setFailStatus('USER_NOT_FOUND');
        $svc->onFail();
        $headers = $svc->getManager()->getResponse()->getHeaders();
        $found = false;
        foreach ($headers as $h) {
            $str = $h . '';
            if (str_contains($str, '?status=USER_NOT_FOUND')) {
                $found = true;
                break;
            }
        }
        $this->assertTrue($found, 'Location header should contain encoded fail status');
    }

    public function testOnFailUrlEncodesStatus() {
        $svc = $this->createRealFailService('https://example.com/error');
        $svc->setFailStatus('error with spaces');
        $svc->onFail();
        $headers = $svc->getManager()->getResponse()->getHeaders();
        $found = false;
        foreach ($headers as $h) {
            $str = $h . '';
            if (str_contains($str, '?status=' . urlencode('error with spaces'))) {
                $found = true;
                break;
            }
        }
        $this->assertTrue($found, 'Fail status should be URL-encoded in the location header');
    }

    public function testOnFailWithEmptyStatus() {
        $svc = $this->createRealFailService('https://example.com/fail');
        $svc->onFail();
        $headers = $svc->getManager()->getResponse()->getHeaders();
        $found = false;
        foreach ($headers as $h) {
            $str = $h . '';
            if (str_contains($str, 'https://example.com/fail?status=')) {
                $found = true;
                break;
            }
        }
        $this->assertTrue($found, 'Location header should still include ?status= even when empty');
    }

    public function testOnFailAcceptsNullUser() {
        $svc = $this->createRealFailService();
        // Should not throw
        $svc->onFail(null);
        $this->assertSame(401, $svc->getManager()->getResponse()->getCode());
    }

    public function testOnFailAcceptsUserObject() {
        $svc = $this->createRealFailService();
        $svc->onFail(new TestUser(99));
        $this->assertSame(401, $svc->getManager()->getResponse()->getCode());
    }
}
