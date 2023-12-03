<?php
namespace oshco\adfs;

use Exception;
use webfiori\file\File;
use webfiori\json\Json;
use webfiori\json\JsonI;
use webfiori\ui\HTMLNode;
use webfiori\ui\TemplateCompiler;
/**
 * A class which is used to represent ADFS response.
 *
 */
class ADFSResponse implements JsonI {
    private $appName;
    private $isSuccess;
    private $username;
    private $xmlString;
    /**
     * Creates new instance of the class.
     * 
     * @param string $samlResponse An XML string that represents SAML response.
     */
    public function __construct(string $samlResponse) {
        $this->xmlString = base64_decode($samlResponse);
        
        $node = TemplateCompiler::fromHTMLText($this->xmlString, false);

        $statusNode = $node->getChild(1)->getChild(0);
        $this->isSuccess = $statusNode->getAttribute('value') === 'urn:oasis:names:tc:SAML:2.0:status:Success';
        $this->checkUsernameandAppName($node);
    }
    private function checkUsernameandAppName(HTMLNode $node) {
        
        $xNodes = $node->getChildrenByTag('attributevalue');
        if (count($xNodes) == 0) {
            throw new Exception("The attribute 'username' is missing from SAML response. Please add it in ADFS.");
        }
        $usernameNode = $xNodes->get(0);
        $this->username = strtolower($usernameNode->getChild(0)->getText());
        $this->appName = str_replace('_', ' ', $node->getAttribute('inresponseto'));
    }
    /**
     * 
     * @return string
     */
    public function __toString() {
        return $this->toJSON().'';
    }
    /**
     * Returns the name of the application at which the user is trying to access.
     * 
     * @return string
     */
    public function getAppName() : string {
        return $this->appName;
    }
    /**
     * Returns the username that was trying to authenticate.
     * 
     * @return string
     */
    public function getUserName() : string {
        return $this->username;
    }
    /**
     * Returns XML tree of SAML response which was given by ADFS.
     * 
     * @return string
     */
    public function getXMLString() : string {
        return HTMLNode::createTextNode($this->xmlString, false)->toXML();
    }
    /**
     * Checks if SAML response status is success or fail.
     * 
     * @return bool If success, true is returned. False if not.
     */
    public function isSuccess() : bool {
        return $this->isSuccess;
    }
    /**
     * Store ADFS response in XML file.
     * 
     * The file can be used to debug any issues related to ADFS authentication.
     */
    public function storeResponse() {
        $user = explode('@', $this->getUserName())[0];
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
            'isSuccess' => $this->isSuccess,
            'username' => $this->getUserName(),
            //'asXmlString' => $this->getXMLString()
        ]);
    }
}
