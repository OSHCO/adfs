<?php
namespace Oshco\Adfs;

use DOMDocument;
use DOMElement;
use DOMXPath;
use WebFiori\File\File;
use WebFiori\Json\Json;
use WebFiori\Json\JsonI;
use WebFiori\Ui\HTMLNode;

/**
 * A class which is used to represent ADFS response.
 *
 * Creating an instance only parses the response. Nothing it contains can be
 * trusted until it has been checked with ADFSResponseValidator::validate().
 * Before validation, the getters return values read from the raw (unverified)
 * XML, which is only suitable for logging. After validation, they return
 * values read from the signed assertion, and isVerified() returns true.
 */
class ADFSResponse implements JsonI {
    /**
     * The largest decoded SAML response accepted, in bytes.
     */
    public const MAX_SIZE = 1048576;
    public const NS_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';
    public const NS_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';
    public const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    private string $appName;
    private ?string $assertionId = null;
    /**
     * @var array<string, string[]>
     */
    private array $attributes = [];
    private DOMDocument $doc;
    private ?string $issuer = null;
    private ?string $nameId = null;
    private ?string $nameIdFormat = null;
    private ?int $notOnOrAfter = null;
    private string $statusCode;
    private string $username;
    private bool $verified = false;
    private string $xmlString;

    /**
     * Creates new instance of the class.
     *
     * @param string $samlResponse The base64-encoded SAML response, as posted
     * by ADFS in the 'SAMLResponse' parameter.
     *
     * @throws SAMLValidationException If the response is not valid base64, is
     * too large, contains a DOCTYPE or is not a SAML 2.0 Response document.
     */
    public function __construct(string $samlResponse) {
        $decoded = base64_decode(trim($samlResponse), true);

        if ($decoded === false || $decoded === '') {
            throw new SAMLValidationException(SAMLValidationException::REASON_MALFORMED, 'SAML response is not valid base64.');
        }
        $this->xmlString = $decoded;
        $this->doc = self::parseXml($decoded);

        $xpath = self::createXPath($this->doc);
        $root = $this->doc->documentElement;
        $this->statusCode = $xpath->evaluate('string(samlp:Status/samlp:StatusCode/@Value)', $root);
        $this->appName = str_replace('_', ' ', $root->getAttribute('InResponseTo'));

        // Unverified values, kept for logging and for backward compatibility.
        $assertion = $xpath->query('saml:Assertion', $root)->item(0);
        $this->username = '';

        if ($assertion instanceof DOMElement) {
            $value = $xpath->query('saml:AttributeStatement/saml:Attribute/saml:AttributeValue', $assertion)->item(0);

            if ($value !== null) {
                $this->username = strtolower(trim($value->textContent));
            }
        }
    }

    /**
     * Returns the response as a JSON string.
     *
     * @return string
     */
    public function __toString() {
        return $this->toJSON().'';
    }

    /**
     * Creates an XPath object with the SAML and XML-DSig prefixes registered.
     *
     * The prefixes are 'samlp' (protocol), 'saml' (assertion) and 'ds' (signature).
     *
     * @param DOMDocument $doc The document to query.
     *
     * @return DOMXPath
     */
    public static function createXPath(DOMDocument $doc): DOMXPath {
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('samlp', self::NS_PROTOCOL);
        $xpath->registerNamespace('saml', self::NS_ASSERTION);
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        return $xpath;
    }

    /**
     * Returns the name of the application at which the user is trying to access.
     *
     * The name is taken from the InResponseTo value, with underscores replaced
     * by spaces. Once verified, only a value covered by the signature is used.
     *
     * @return string
     */
    public function getAppName(): string {
        return $this->appName;
    }

    /**
     * Returns the ID of the assertion.
     *
     * Applications can use it, together with getNotOnOrAfter(), to reject
     * assertions that were already used.
     *
     * @return string|null Null if the response was not verified.
     */
    public function getAssertionId(): ?string {
        return $this->assertionId;
    }

    /**
     * Returns the values of a named attribute from the assertion.
     *
     * @param string $name The attribute name, e.g.
     * 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn'.
     *
     * @return string[] The values, or an empty array if the attribute is
     * missing or the response was not verified.
     */
    public function getAttribute(string $name): array {
        return $this->attributes[$name] ?? [];
    }

    /**
     * Returns all attributes of the assertion.
     *
     * @return array<string, string[]> Attribute name mapped to its values. Empty
     * if the response was not verified.
     */
    public function getAttributes(): array {
        return $this->attributes;
    }

    /**
     * Returns the parsed response document.
     *
     * @internal Used by ADFSResponseValidator.
     *
     * @return DOMDocument
     */
    public function getDocument(): DOMDocument {
        return $this->doc;
    }

    /**
     * Returns the issuer of the assertion.
     *
     * @return string|null Null if the response was not verified.
     */
    public function getIssuer(): ?string {
        return $this->issuer;
    }

    /**
     * Returns the NameID of the assertion subject.
     *
     * @return string|null Null if missing or if the response was not verified.
     */
    public function getNameId(): ?string {
        return $this->nameId;
    }

    /**
     * Returns the format of the NameID, e.g.
     * 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'.
     *
     * @return string|null Null if missing or if the response was not verified.
     */
    public function getNameIdFormat(): ?string {
        return $this->nameIdFormat;
    }

    /**
     * Returns the time after which the assertion must not be accepted.
     *
     * This is the earliest of the Conditions and subject confirmation expiry
     * times. Applications that store used assertion IDs can drop an ID after
     * this time.
     *
     * @return int|null A Unix timestamp, or null if the response was not verified.
     */
    public function getNotOnOrAfter(): ?int {
        return $this->notOnOrAfter;
    }

    /**
     * Returns the decoded XML of the response, exactly as received.
     *
     * @return string
     */
    public function getRawXML(): string {
        return $this->xmlString;
    }

    /**
     * Returns the status code of the response.
     *
     * @return string e.g. 'urn:oasis:names:tc:SAML:2.0:status:Success'.
     */
    public function getStatusCode(): string {
        return $this->statusCode;
    }

    /**
     * Returns the username that was trying to authenticate.
     *
     * The value is lowercased. Before verification it is the first attribute
     * value in the raw XML, which can be forged and must not be used to sign
     * anyone in.
     *
     * @return string
     */
    public function getUserName(): string {
        return $this->username;
    }

    /**
     * Returns XML tree of SAML response which was given by ADFS.
     *
     * An XML declaration is added if the response has none.
     *
     * @return string
     */
    public function getXMLString(): string {
        return HTMLNode::createTextNode($this->xmlString, false)->toXML();
    }

    /**
     * Checks if SAML response status is success or fail.
     *
     * This only reflects the status code. It does not mean the response is
     * authentic; use isVerified() for that.
     *
     * @return bool If success, true is returned. False if not.
     */
    public function isSuccess(): bool {
        return $this->statusCode === self::STATUS_SUCCESS;
    }

    /**
     * Checks if the response passed ADFSResponseValidator::validate().
     *
     * @return bool
     */
    public function isVerified(): bool {
        return $this->verified;
    }

    /**
     * Parses an XML string safely.
     *
     * Documents with a DOCTYPE are rejected, network access is disabled, and
     * entities are not substituted.
     *
     * @param string $xml The XML to parse.
     *
     * @return DOMDocument A document whose root is a SAML 2.0 protocol Response.
     *
     * @throws SAMLValidationException If the XML is unsafe, too large or not a SAML Response.
     */
    public static function parseXml(string $xml): DOMDocument {
        if (strlen($xml) > self::MAX_SIZE) {
            throw new SAMLValidationException(SAMLValidationException::REASON_MALFORMED, 'SAML response exceeds the maximum allowed size.');
        }

        if (stripos($xml, '<!DOCTYPE') !== false) {
            throw new SAMLValidationException(SAMLValidationException::REASON_DOCTYPE_NOT_ALLOWED, 'SAML response must not contain a DOCTYPE declaration.');
        }
        $doc = new DOMDocument();
        $previous = libxml_use_internal_errors(true);
        $loaded = $doc->loadXML($xml, LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if (!$loaded || $doc->doctype !== null) {
            throw new SAMLValidationException(SAMLValidationException::REASON_MALFORMED, 'SAML response is not well-formed XML.');
        }
        $root = $doc->documentElement;

        if ($root === null || $root->namespaceURI !== self::NS_PROTOCOL || $root->localName !== 'Response') {
            throw new SAMLValidationException(SAMLValidationException::REASON_MALFORMED, 'Document is not a SAML 2.0 Response.');
        }

        return $doc;
    }

    /**
     * Stores the values read from the verified assertion.
     *
     * @internal Called by ADFSResponseValidator after all checks pass. Calling
     * it from anywhere else bypasses validation.
     *
     * @param array $claims The keys 'username', 'appName', 'assertionId',
     * 'issuer', 'nameId', 'nameIdFormat', 'attributes' and 'notOnOrAfter'.
     */
    public function setVerifiedClaims(array $claims): void {
        $this->username = $claims['username'];
        $this->appName = $claims['appName'];
        $this->assertionId = $claims['assertionId'];
        $this->issuer = $claims['issuer'];
        $this->nameId = $claims['nameId'];
        $this->nameIdFormat = $claims['nameIdFormat'];
        $this->attributes = $claims['attributes'];
        $this->notOnOrAfter = $claims['notOnOrAfter'];
        $this->verified = true;
    }

    /**
     * Store ADFS response in XML file.
     *
     * The file can be used to debug any issues related to ADFS authentication.
     * The username is reduced to safe characters before it is used in the
     * file name.
     */
    public function storeResponse() {
        $user = preg_replace('/[^a-z0-9._-]/', '_', explode('@', $this->getUserName())[0]);
        $file = new File(ROOT_PATH.DS.APP_DIR.DS.'sto'.DS.'adfs'.DS.date('Y-m-d H-i-s').'-'.$user.'.log');
        $file->setRawData($this->getXMLString());
        $file->create();
        $file->write();
    }

    /**
     *
     * @return Json
     */
    public function toJSON(): Json {
        return new Json([
            'appName' => $this->getAppName(),
            'isSuccess' => $this->isSuccess(),
            'isVerified' => $this->isVerified(),
            'username' => $this->getUserName(),
        ]);
    }
}
