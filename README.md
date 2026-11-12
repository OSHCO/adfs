# ADFS Integration for WebFiori

A PHP library that provides ADFS (Active Directory Federation Services) single sign-on integration for [WebFiori](https://webfiori.com) based applications using SAML 2.0.

## Requirements

- PHP 8.1 or later, with the `dom` and `openssl` extensions
- [WebFiori HTTP](https://github.com/WebFiori/http) 6.0+
- [WebFiori UI](https://github.com/WebFiori/ui) 4.0+
- [WebFiori File](https://github.com/WebFiori/file) 2.1+
- [WebFiori JsonX](https://github.com/WebFiori/jsonx) 5.0+
- [xmlseclibs](https://github.com/robrichards/xmlseclibs) 3.1.5 (installed automatically, used to verify XML signatures)

## Installation

```bash
composer require oshco/adfs
```

## How It Works

1. Your application builds a SAML request using `SAMLRequest` and redirects the user to the ADFS server.
2. The user authenticates on the ADFS login page.
3. ADFS posts a signed SAML response back to your application's callback endpoint.
4. Your `ADFSVerificationService` subclass parses the response and validates it with an `ADFSResponseValidator`: the signature must match the ADFS token-signing certificate, and the assertion must be addressed to your application and still valid.
5. Only then does the service look up the user and call `onSuccess()`. Any failure calls `onFail()`.

## Classes

| Class / Interface | Description |
|---|---|
| [`ADFSUser`](Oshco/Adfs/ADFSUser.php) | Interface representing an authenticated user. Requires `getId()`. |
| [`SAMLRequest`](Oshco/Adfs/SAMLRequest.php) | Builds a SAML 2.0 authentication request. Supports XML generation and base64+deflate encoding for HTTP-Redirect binding. |
| [`ADFSResponse`](Oshco/Adfs/ADFSResponse.php) | Parses a base64-encoded SAML response from ADFS. After validation, exposes the username, application name, NameID, attributes, assertion ID and expiry from the signed assertion. |
| [`ADFSResponseValidator`](Oshco/Adfs/ADFSResponseValidator.php) | Verifies the signature and conditions of a response. Holds the ADFS certificate(s), the expected audience, and optional issuer, recipient and username attribute. |
| [`SAMLValidationException`](Oshco/Adfs/SAMLValidationException.php) | Thrown when a response is malformed or fails validation. `getReason()` returns a stable reason code. |
| [`ADFSVerificationService`](Oshco/Adfs/ADFSVerificationService.php) | Abstract web service that acts as the ADFS callback endpoint. Subclass it to implement `getUser()`, `getValidator()` and `onSuccess()`. |

## Usage

### 1. Implement the `ADFSUser` interface

```php
use Oshco\Adfs\ADFSUser;

class AppUser implements ADFSUser {
    private int $id;
    private string $email;

    public function __construct(int $id, string $email) {
        $this->id = $id;
        $this->email = $email;
    }

    public function getId() {
        return $this->id;
    }
}
```

### 2. Build and send a SAML request

```php
use Oshco\Adfs\SAMLRequest;

$request = new SAMLRequest();
$request->setDestination('https://adfs.example.com/adfs/ls');
$request->setAppID('My Application');
$request->setAppURL('https://myapp.example.com');
$request->setIssueInstant(gmdate('Y-m-d\TH:i:s\Z'));

$encoded = $request->encode();

// Redirect user to ADFS with the encoded SAML request
header('Location: https://adfs.example.com/adfs/ls?SAMLRequest=' . urlencode($encoded));
```

The value passed to `setAppURL()` is the Issuer of the request. ADFS uses it to find the relying party, and puts the relying party identifier in the `Audience` of the response. Use the same value as the audience of the validator.

### 3. Configure a validator

```php
use Oshco\Adfs\ADFSResponseValidator;

$validator = new ADFSResponseValidator(
    // ADFS token-signing certificate (PEM, or the base64 body from the
    // federation metadata). Pass an array to accept several during a rollover.
    $adfsSigningCertificate,
    // The relying party identifier of this application in ADFS.
    'https://myapp.example.com'
);

// Recommended:
$validator->setIssuer('http://adfs.example.com/adfs/services/trust');
$validator->setRecipient('https://myapp.example.com/apis/adfs-verify');
$validator->setUsernameAttribute('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn');
```

| Setting | Required | Description |
|---|---|---|
| Certificate(s) | Yes | The ADFS **token-signing** certificate. Get it from ADFS Management (Service → Certificates) or from `https://{adfs-host}/FederationMetadata/2007-06/FederationMetadata.xml`. Certificates embedded in a response are never trusted. |
| Audience | Yes | The relying party identifier. Blocks assertions that ADFS issued to other applications. |
| `setIssuer()` | Recommended | The ADFS Federation Service Identifier. |
| `setRecipient()` | Recommended | The URL of your verification endpoint, as configured as the SAML assertion consumer endpoint in ADFS. |
| `setUsernameAttribute()` | Recommended | The claim that holds the username. When not set, the first attribute value is used, as in version 2, and reordering claim rules in ADFS would change who is signed in. |
| `setClockSkew()` | No | Allowed clock difference in seconds (default 180, maximum 600). |
| `setAllowSha1()` | No | Accept SHA-1 signatures. Off by default; enable only for a relying party that cannot use SHA-256. |

### 4. Create a verification service

Extend `ADFSVerificationService` and implement the abstract methods:

```php
use Oshco\Adfs\ADFSResponse;
use Oshco\Adfs\ADFSResponseValidator;
use Oshco\Adfs\ADFSUser;
use Oshco\Adfs\ADFSVerificationService;

class MyVerificationService extends ADFSVerificationService {

    public function __construct() {
        parent::__construct('adfs-verify', 'https://myapp.example.com/login-failed');
    }

    public function getValidator(): ADFSResponseValidator {
        // Build the validator from your configuration (see step 3).
    }

    public function getUser(string $username): ?ADFSUser {
        // $username comes from the verified assertion.
        // getSamlResponse() gives access to the NameID and all attributes.
        // Return an ADFSUser instance or null if not found.
    }

    public function onSuccess(ADFSUser $user) {
        // User authenticated successfully
        // Set session, redirect to dashboard, etc.
    }

    public function onFail(?ADFSUser $user = null) {
        // Optional: log why, then redirect.
        error_log('ADFS login failed: '.$this->getError().' '.$this->getErrorMessage());
        parent::onFail($user);
    }
}
```

When ADFS posts back to your endpoint, the service will:
- Read `SAMLResponse` from the POST body. A request without it gets a 400 response and neither handler is called.
- Parse and validate the response. On failure, call `onFail()`.
- Call `isAssertionReplayed()` (see below). If it returns true, call `onFail()`.
- Call `getUser()` with the verified username, then `onSuccess()` if a user is found, or `onFail()` if not (redirects to the fail URL with a `?status=` parameter).

`getError()` returns why the last request failed: one of the `SAMLValidationException::REASON_*` codes, `ADFSVerificationService::ERROR_MISSING_RESPONSE`, or `ADFSVerificationService::ERROR_USER_NOT_FOUND`. `getErrorMessage()` returns details for logs. Do not show it to users.

### 5. Reject replayed assertions (recommended)

A valid assertion can be posted again until it expires. To block this, store each assertion ID until its expiry and reject IDs you have seen:

```php
public function isAssertionReplayed(ADFSResponse $response): bool {
    $id = $response->getAssertionId();

    if ($this->usedAssertions->has($id)) {
        return true;
    }
    // Keep the ID until the assertion can no longer be accepted.
    $this->usedAssertions->put($id, $response->getNotOnOrAfter());

    return false;
}
```

The default implementation returns false, which does not detect replays.

### 6. Inspect the SAML response

```php
use Oshco\Adfs\ADFSResponse;
use Oshco\Adfs\SAMLValidationException;

$response = new ADFSResponse($_POST['SAMLResponse']); // throws on malformed input

try {
    $validator->validate($response);
} catch (SAMLValidationException $e) {
    $e->getReason();  // e.g. SAMLValidationException::REASON_INVALID_SIGNATURE
}

$response->isVerified();    // true only after validate() succeeded
$response->isSuccess();     // true if the status code is Success
$response->getUserName();   // authenticated username (lowercased)
$response->getAppName();    // application name from InResponseTo
$response->getNameId();     // NameID of the subject
$response->getAttribute('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn'); // string[]
$response->getAttributes(); // all attributes: name => string[]
$response->getAssertionId();
$response->getNotOnOrAfter(); // Unix timestamp
$response->getXMLString();  // raw XML of the SAML response
$response->storeResponse(); // save response to file for debugging
```

Before `validate()` succeeds, the getters return values read from the raw XML, which anyone can forge. Use them for logging only.

## Security

`ADFSResponseValidator` accepts a response only if:

- The status is Success and the response contains exactly one unencrypted `Assertion`, as a direct child of the `Response`.
- No two elements share an ID.
- The `Assertion` or the `Response` (or both) is signed, and every signature present verifies against one of the configured certificates.
- Each signature references exactly the element it is attached to, uses RSA with SHA-256/384/512 (SHA-1 only if allowed), and uses only enveloped-signature and canonicalization transforms.
- `Conditions` contain the configured audience, and the current time is within `NotBefore` / `NotOnOrAfter`.
- A bearer `SubjectConfirmation` has not expired and, if configured, matches the recipient.
- The issuer matches, if configured.
- `InResponseTo` on the `Response`, if present, matches the one inside the assertion. The application name is taken from a signed value only.

Documents with a `DOCTYPE` and responses larger than 1 MB are rejected before parsing. Encrypted assertions are not supported.

Replay detection needs storage and is left to the application; see step 5.

## Upgrading from 2.x to 3.0

Version 2 did not verify SAML signatures: any well-formed XML posted to the verification endpoint was accepted, so anyone who could reach the endpoint could sign in as any user. **Upgrade all applications.**

1. Implement `getValidator()` in your `ADFSVerificationService` subclass, with the ADFS token-signing certificate and the relying party identifier.
2. If your `onFail()` checks `getSamlResponse()->isSuccess()` to tell failures apart, use `getError()` instead. `getSamlResponse()` can now be null (malformed input) or unverified (validation failed).
3. `new ADFSResponse()` now throws `SAMLValidationException` for input that is not a SAML response, instead of a generic `Exception` (or an error). A missing username is reported by the validator with reason `missing_username`.
4. `getUserName()` and `getAppName()` return values from the signed assertion after validation. `getAppName()` on the service returns an empty string until the response is verified.
5. `SAMLResponse` is read from the POST body only. Reading it from the query string never worked in version 2.
6. If ADFS signs with SHA-1, switch the relying party to SHA-256 (Relying Party → Properties → Advanced), or call `setAllowSha1(true)`.

## Running Tests

```bash
composer test
```

The tests sign responses with throwaway keys generated at runtime, and cover forged, tampered and wrapped signatures, wrong keys and algorithms, audience, issuer, recipient and time checks.

## Maintainer

- Ibrahim BinAlshikh (i.binalshikh@oshco.com)

## License

This library is licensed under the [MIT License](LICENSE).

Copyright (c) 2023 Olayan Saudi Holding Company (OSHCO)
