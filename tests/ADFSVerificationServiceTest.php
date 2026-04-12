<?php
namespace oshco\adfs\tests;

use oshco\adfs\ADFSUser;
use oshco\adfs\ADFSVerificationService;
use PHPUnit\Framework\TestCase;

/**
 * A concrete test implementation of ADFSVerificationService.
 */
class TestVerificationService extends ADFSVerificationService {
    private $mockUser;
    private $successCalled = false;
    private $failCalled = false;
    private $lastUser;

    public function __construct(string $name = 'test-verify', string $failRedirect = 'https://example.com/fail') {
        parent::__construct($name, $failRedirect);
    }

    public function setMockUser(?ADFSUser $user) {
        $this->mockUser = $user;
    }

    public function getUser(string $username): ?ADFSUser {
        return $this->mockUser;
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
        $user = new TestUser(42);
        $svc->setMockUser($user);

        $_POST['SAMLResponse'] = SAMLResponseBuilder::buildSuccess('testuser@example.com', 'TestApp');
        $svc->processRequest();

        $this->assertTrue($svc->wasSuccessCalled());
        $this->assertFalse($svc->wasFailCalled());
        $this->assertSame(42, $svc->getLastUser()->getId());
        $this->assertSame('TestApp', $svc->getAppName());
    }

    public function testProcessRequestCallsOnFailWhenUserNotFound() {
        $svc = new TestVerificationService();
        $svc->setMockUser(null);

        $_POST['SAMLResponse'] = SAMLResponseBuilder::buildSuccess('unknown@example.com');
        $svc->processRequest();

        $this->assertTrue($svc->wasFailCalled());
        $this->assertFalse($svc->wasSuccessCalled());
    }

    public function testProcessRequestCallsOnFailWhenSAMLFails() {
        $svc = new TestVerificationService();
        $user = new TestUser(1);
        $svc->setMockUser($user);

        $_POST['SAMLResponse'] = SAMLResponseBuilder::buildFailure();
        $svc->processRequest();

        $this->assertTrue($svc->wasFailCalled());
        $this->assertFalse($svc->wasSuccessCalled());
    }

    public function testProcessRequestSetsSamlResponse() {
        $svc = new TestVerificationService();
        $svc->setMockUser(new TestUser());

        $_POST['SAMLResponse'] = SAMLResponseBuilder::buildSuccess('admin@example.com', 'My_App');
        $svc->processRequest();

        $this->assertNotNull($svc->getSamlResponse());
        $this->assertTrue($svc->getSamlResponse()->isSuccess());
        $this->assertSame('admin@example.com', $svc->getSamlResponse()->getUserName());
        $this->assertSame('My App', $svc->getAppName());
    }

    protected function tearDown(): void {
        unset($_POST['SAMLResponse']);
    }
}
