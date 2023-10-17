<?php
namespace oshco\adfs;

use oshco\entity\ADFSUser;
use oshco\entity\adfs\ADFSResponse;
use webfiori\framework\App;
use webfiori\framework\EAbstractWebService;
use webfiori\http\Response;


/**
 * A class that contains the implementation of the service which is used to
 * verify the status of ADFS response.
 */
abstract class ADFSVerificationService extends EAbstractWebService {
    /**
     * 
     * @var ADFSResponse
     */
    private $samlResponse;
    /**
     * Creates new instance of the class.
     * 
     * @param string $name The name of the service.
     */
    public function __construct(string $name = 'verify-identity') {
        parent::__construct($name);
        $this->addRequestMethod('POST');
        $this->addRequestMethod('GET');
        $this->addParameters([
            'SAMLResponse' => [
                'type' => 'string'
            ]
        ]);
        $this->setOnFailRedirect(App::getConfig()->getHomePage());
        $this->setFailStatus('');
    }
    /**
     * Returns a user given its username.
     * 
     * The username of the user will be taken from ADFS response as received.
     * The method must be implemented in a way that it looks for such user
     * in the application's database which has provided username/email and
     * return its information as an object of type 'oshco\adfs\ADFSUser'.
     * If no such user was found, null should be returned.
     * 
     * @return ADFSUser|null
     */
    public abstract function getUser(string $username);
    /**
     * Send the response to the callback which was set when ADFS authentication
     * fails.
     * 
     * The method will send a response with code 401 to the URL which was set
     * on failure. Additionally, the URL will have extra parameter at the
     * end which hold status code of the failure with name 'status'.
     * 
     * @param ADFSUser|null $user
     */
    public function onFail(ADFSUser $user = null) {
        Response::addHeader('location', $this->getOnFailRedirect().'?status='. urlencode($this->getFailStatus()));
        Response::setCode(401);
        Response::send();
    }
    /**
     * Execute the instructions in case of ADFS success.
     * 
     * This method must be implemented in a way that it executes a set of
     * instructions when ADFS returns a success status.
     * 
     * @param ADFSUser The user who was signed in using ADFS.
     */
    public abstract function onSuccess(ADFSUser $user);
    private $failStatus;
    /**
     * Returns a string that represents ADFS fail status.
     * 
     * @return string Default return value is empty string.
     */
    public function getFailStatus() : string {
        return $this->failStatus;
    }
    /**
     * Returns a string that represents ADFS fail redirect URL.
     * 
     * @return string Default return value is the base URL of the application.
     */
    public function getOnFailRedirect() : string {
        return $this->onFailRedirect;
    }
    /**
     * Sets a string to use as status code for ADFS failure.
     * 
     * @param string $failStatus
     */
    public function setFailStatus(string $failStatus) {
        $this->failStatus = $failStatus;
    }
    private $onFailRedirect;
    /**
     * Sets a URL that the response will be redirected to in case of ADFS failure.
     * 
     * @param string $url
     */
    public function setOnFailRedirect(string $url) {
        $this->onFailRedirect = $url;
    }
    /**
     * Returns a string that represents the application name as set in ADFS configuration.
     * 
     * The value of this property is set by ADFS server.
     * 
     * @return string Default return value is empty string.
     */
    public function getAppName() : string {
        if ($this->samlResponse !== null) {
            return $this->samlResponse->getAppName();
        }
        
        return '';
    }
    /**
     * Returns SAML response that was received from ADFS server.
     * 
     * @return ADFSResponse|null If set, it is returned as an object. Other than
     * that, null is returned.
     */
    public function getSamlResponse() {
        return $this->samlResponse;
    }
    /**
     * Process the request.
     */
    public function processRequest() {
        $this->samlResponse = new ADFSResponse($_POST['SAMLResponse']);

        if ($this->getSamlResponse()->isSuccess()) {
            $username = $this->getSamlResponse()->getUserName();
            $user = $this->getUser($username);

            if ($user === null) {
                $this->onFail();
            } else {
                $this->onSuccess($user);
            }
        } else {
            $this->onFail();
        }
    }
}
