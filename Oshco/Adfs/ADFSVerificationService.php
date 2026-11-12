<?php
namespace Oshco\Adfs;

use WebFiori\Http\ParamOption;
use WebFiori\Http\ParamType;
use WebFiori\Http\RequestMethod;
use WebFiori\Http\WebService;


/**
 * A class that contains the implementation of the service which is used to
 * verify the status of ADFS response.
 *
 * The service parses the posted SAML response and validates it with the
 * validator returned by getValidator(). Only a response that passes
 * validation reaches getUser() and onSuccess(). Any failure calls onFail(),
 * and getError() tells why.
 */
abstract class ADFSVerificationService extends WebService {
    /**
     * The value of getError() when the request has no SAMLResponse parameter.
     */
    public const ERROR_MISSING_RESPONSE = 'missing_response';
    /**
     * The value of getError() when the response is valid but getUser()
     * returned null.
     */
    public const ERROR_USER_NOT_FOUND = 'user_not_found';

    private ?string $error = null;
    private ?string $errorMessage = null;
    private $failStatus;
    private $onFailRedirect;
    /**
     *
     * @var ADFSResponse|null
     */
    private $samlResponse;
    /**
     * Creates new instance of the class.
     *
     * @param string $name The name of the service.
     * @param string $failRedirect A URL at which the user will be redirected to in case of ADFS login fail.
     */
    public function __construct(string $name = 'verify', string $failRedirect = '') {
        parent::__construct($name);
        $this->addRequestMethod(RequestMethod::POST);
        $this->addRequestMethod(RequestMethod::GET);
        $this->addParameters([
            'SAMLResponse' => [
                ParamOption::TYPE => ParamType::STRING,
                ParamOption::OPTIONAL => true
            ]
        ]);
        $this->setOnFailRedirect($failRedirect);
        $this->setFailStatus('');
    }
    /**
     * Returns the application name as set in the SAML request.
     *
     * Only a verified response is used, so the value cannot be forged.
     *
     * @return string Default return value is empty string.
     */
    public function getAppName(): string {
        if ($this->samlResponse !== null && $this->samlResponse->isVerified()) {
            return $this->samlResponse->getAppName();
        }

        return '';
    }
    /**
     * Returns the reason of the last failure.
     *
     * @return string|null One of the SAMLValidationException::REASON_*
     * constants, ERROR_MISSING_RESPONSE or ERROR_USER_NOT_FOUND. Null if
     * nothing failed.
     */
    public function getError(): ?string {
        return $this->error;
    }
    /**
     * Returns a description of the last failure, for logs.
     *
     * The message may contain details from the response and must not be
     * shown to end users.
     *
     * @return string|null Null if nothing failed.
     */
    public function getErrorMessage(): ?string {
        return $this->errorMessage;
    }
    /**
     * Returns a string that represents ADFS fail status.
     *
     * @return string Default return value is empty string.
     */
    public function getFailStatus(): string {
        return $this->failStatus;
    }
    /**
     * Returns a string that represents ADFS fail redirect URL.
     *
     * @return string Default return value is the base URL of the application.
     */
    public function getOnFailRedirect(): string {
        return $this->onFailRedirect;
    }
    /**
     * Returns SAML response that was received from ADFS server.
     *
     * The response may be unverified, e.g. when onFail() is called because
     * validation failed. Check ADFSResponse::isVerified() before trusting it.
     *
     * @return ADFSResponse|null If set, it is returned as an object. Other than
     * that, null is returned.
     */
    public function getSamlResponse() {
        return $this->samlResponse;
    }
    /**
     * Returns a user given its username.
     *
     * The username is taken from the verified SAML assertion. The method must
     * be implemented in a way that it looks for such user in the application's
     * database which has provided username/email and return its information
     * as an object of type 'Oshco\Adfs\ADFSUser'. The full verified response,
     * including NameID and all attributes, is available from getSamlResponse().
     * If no such user was found, null should be returned.
     *
     * @return ADFSUser|null
     */
    abstract public function getUser(string $username);
    /**
     * Returns the validator used to check SAML responses.
     *
     * It must be configured with the ADFS token-signing certificate(s) and
     * the identifier of this application in ADFS.
     *
     * @return ADFSResponseValidator
     */
    abstract public function getValidator(): ADFSResponseValidator;
    /**
     * Checks if an assertion was already used.
     *
     * Override it to reject replayed assertions: store the ID from
     * ADFSResponse::getAssertionId() until ADFSResponse::getNotOnOrAfter(),
     * and return true if the ID was seen before. The default implementation
     * does not detect replays.
     *
     * @param ADFSResponse $response A verified response.
     *
     * @return bool True to reject the response.
     */
    public function isAssertionReplayed(ADFSResponse $response): bool {
        return false;
    }
    public function isAuthorized(): bool {
        return true;
    }
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
    public function onFail(?ADFSUser $user = null) {
        $this->getManager()->getResponse()->addHeader('location', $this->getOnFailRedirect().'?status='.urlencode($this->getFailStatus()));
        $this->getManager()->getResponse()->setCode(401);
        $this->getManager()->getResponse()->send();
    }
    /**
     * Execute the instructions in case of ADFS success.
     *
     * This method must be implemented in a way that it executes a set of
     * instructions when ADFS returns a success status.
     *
     * @param ADFSUser The user who was signed in using ADFS.
     */
    abstract public function onSuccess(ADFSUser $user);
    /**
     * Process the request.
     *
     * The response is read from the POST body only, as ADFS uses the
     * HTTP-POST binding.
     */
    public function processRequest() {
        $this->samlResponse = null;
        $this->error = null;
        $this->errorMessage = null;
        $encoded = $_POST['SAMLResponse'] ?? null;

        if (!is_string($encoded) || trim($encoded) === '') {
            $this->error = self::ERROR_MISSING_RESPONSE;
            $this->errorMessage = 'SAMLResponse is not provided.';
            $this->sendResponse('SAMLResponse is not provided.', 400, 'error');

            return;
        }

        try {
            $this->samlResponse = new ADFSResponse($encoded);
            $this->getValidator()->validate($this->samlResponse);

            if ($this->isAssertionReplayed($this->samlResponse)) {
                throw new SAMLValidationException(SAMLValidationException::REASON_REPLAYED, 'The assertion was already used.');
            }
        } catch (SAMLValidationException $e) {
            $this->error = $e->getReason();
            $this->errorMessage = $e->getMessage();
            $this->onFail();

            return;
        }
        $user = $this->getUser($this->samlResponse->getUserName());

        if ($user === null) {
            $this->error = self::ERROR_USER_NOT_FOUND;
            $this->errorMessage = 'No user matches '.$this->samlResponse->getUserName().'.';
            $this->onFail();

            return;
        }
        $this->onSuccess($user);
    }
    /**
     * Sets a string to use as status code for ADFS failure.
     *
     * @param string $failStatus
     */
    public function setFailStatus(string $failStatus) {
        $this->failStatus = $failStatus;
    }
    /**
     * Sets a URL that the response will be redirected to in case of ADFS failure.
     *
     * @param string $url
     */
    public function setOnFailRedirect(string $url) {
        $this->onFailRedirect = $url;
    }
}
