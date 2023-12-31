<?php
namespace oshco\adfs;

use webfiori\ui\HTMLNode;

/**
 * A class which is used to build SAML request based on user inputs.
 */
class SAMLRequest {
    private $appId;
    private $appUrl;
    private $destination;
    private $issueDate;
    public function __construct() {
        $this->destination = '';
        $this->appId = '';
        $this->appUrl = '';
        $this->issueDate = '';
    }
    public function __toString() {
        $node = new HTMLNode('saml2p:AuthnRequest');
        $node->setIsQuotedAttribute(true);
        $node->setAttributes([
            'xmlns:saml2p' => 'urn:oasis:names:tc:SAML:2.0:protocol',
            'Destination' => $this->getDestination(),
            'ForceAuthn' => "false",
            'ID' => $this->getAppID(),
            'IssueInstant' => $this->getIssueInstance(),
            'ProtocolBinding' => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            'Version' => "2.0"
        ]);
        $node->addChild('saml2:Issuer', [
            'xmlns:saml2' => "urn:oasis:names:tc:SAML:2.0:assertion"
        ])->text($this->getAppUrl());

        $node->addChild('saml2p:NameIDPolicy', [
            'AllowCreate' => "true",
            'Format' => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        ])->setIsVoidNode(true);

        return $node->toXML();
    }
    public function encode() {
        return base64_encode(gzdeflate($this.''));
    }
    /**
     * Returns the ID of the application.
     * 
     * The ID will be normally the name of the application as it appears
     * in database.
     * 
     * @return string
     */
    public function getAppID() : string {
        return $this->appId;
    }
    /**
     * Returns the URL of the application.
     * 
     * The URL of the application will act as the identifier of the application
     * on ADFS.
     * 
     * @return string
     */
    public function getAppUrl() : string {
        return $this->appUrl;
    }
    /**
     * Returns the address of the server that will receive SAML request.
     * 
     * @return string The address of the server that will receive SAML request.
     */
    public function getDestination() : string {
        return $this->destination;
    }
    /**
     * Returns the date at which ADFS integration was created.
     * 
     * @return string
     */
    public function getIssueInstance() : string {
        return $this->issueDate;
    }
    /**
     * Sets the ID of the application.
     * 
     * The ID will be normally the name of the application as it appears
     * in database.
     * 
     * @param string $param
     */
    public function setAppID(string $param) {
        $this->appId = str_replace(' ', '_', $param);
    }
    /**
     * Sets the URL of the application.
     * 
     * The URL of the application will act as the identifier of the application
     * on ADFS.
     * 
     * @param string $url
     */
    public function setAppURL(string $url) {
        $this->appUrl = $url;
    }
    /**
     * Sets the URL of ADFS server.
     * 
     * @param string $dest The URL of ADFS server. This can be something like
     * "https://adfs.example.com/adfs/ls"
     */
    public function setDestination(string $dest) {
        $this->destination = $dest;
    }
    /**
     * Sets the date at which ADFS integration was created.
     * 
     * @param string $date
     */
    public function setIssueInstant(string $date) {
        $this->issueDate = $date;
    }
}
