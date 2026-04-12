<?php
namespace oshco\adfs\tests;

/**
 * Helper to build SAML response XML for testing.
 */
class SAMLResponseBuilder {

    public static function buildSuccess(string $username = 'testuser@example.com', string $appId = 'My_App'): string {
        return self::build('urn:oasis:names:tc:SAML:2.0:status:Success', $username, $appId);
    }

    public static function buildFailure(string $username = 'testuser@example.com', string $appId = 'My_App'): string {
        return self::build('urn:oasis:names:tc:SAML:2.0:status:Requester', $username, $appId);
    }

    public static function buildWithoutUsername(string $appId = 'My_App'): string {
        $xml = '<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="' . $appId . '">'
            . '<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://adfs.example.com</saml2:Issuer>'
            . '<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></saml2p:StatusCode></saml2p:Status>'
            . '<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><AttributeStatement></AttributeStatement></Assertion>'
            . '</saml2p:Response>';
        return base64_encode($xml);
    }

    public static function encode(string $xml): string {
        return base64_encode($xml);
    }

    private static function build(string $statusValue, string $username, string $appId): string {
        $xml = '<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="' . $appId . '">'
            . '<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://adfs.example.com</saml2:Issuer>'
            . '<saml2p:Status><saml2p:StatusCode Value="' . $statusValue . '"></saml2p:StatusCode></saml2p:Status>'
            . '<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">'
            . '<AttributeStatement><Attribute Name="username"><AttributeValue>' . $username . '</AttributeValue></Attribute></AttributeStatement>'
            . '</Assertion>'
            . '</saml2p:Response>';
        return base64_encode($xml);
    }
}
