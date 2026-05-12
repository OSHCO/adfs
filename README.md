# ADFS Integration for WebFiori

A PHP library that provides ADFS (Active Directory Federation Services) single sign-on integration for [WebFiori](https://webfiori.com) based applications using SAML 2.0.

## Requirements

- PHP 8.1 or later
- [WebFiori HTTP](https://github.com/WebFiori/http) 5.0+
- [WebFiori UI](https://github.com/WebFiori/ui) 4.0+
- [WebFiori File](https://github.com/WebFiori/file) 2.0+
- [WebFiori JsonX](https://github.com/WebFiori/jsonx) 4.0+

## Installation

```bash
composer require oshco/adfs
```

## How It Works

1. Your application builds a SAML request using `SAMLRequest` and redirects the user to the ADFS server.
2. The user authenticates on the ADFS login page.
3. ADFS posts a SAML response back to your application's callback endpoint.
4. Your `ADFSVerificationService` subclass parses the response, looks up the user, and handles success or failure.

## Classes

| Class / Interface | Description |
|---|---|
| [`ADFSUser`](Oshco/Adfs/ADFSUser.php) | Interface representing an authenticated user. Requires `getId()`. |
| [`SAMLRequest`](Oshco/Adfs/SAMLRequest.php) | Builds a SAML 2.0 authentication request. Supports XML generation and base64+deflate encoding for HTTP-Redirect binding. |
| [`ADFSResponse`](Oshco/Adfs/ADFSResponse.php) | Parses a base64-encoded SAML response from ADFS. Extracts success/failure status, username, and application name. |
| [`ADFSVerificationService`](Oshco/Adfs/ADFSVerificationService.php) | Abstract web service that acts as the ADFS callback endpoint. Subclass it to implement `getUser()` and `onSuccess()`. |

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

### 3. Create a verification service

Extend `ADFSVerificationService` and implement the two abstract methods:

```php
use Oshco\Adfs\ADFSUser;
use Oshco\Adfs\ADFSVerificationService;

class MyVerificationService extends ADFSVerificationService {

    public function __construct() {
        parent::__construct('adfs-verify', 'https://myapp.example.com/login-failed');
    }

    public function getUser(string $username): ?ADFSUser {
        // Look up the user in your database by username/email
        // Return an ADFSUser instance or null if not found
    }

    public function onSuccess(ADFSUser $user) {
        // User authenticated successfully
        // Set session, redirect to dashboard, etc.
    }
}
```

When ADFS posts back to your endpoint, the service will:
- Parse the SAML response
- Call `getUser()` with the authenticated username
- Call `onSuccess()` if the user is found, or `onFail()` if not (redirects to the fail URL with a `?status=` parameter)

### 4. Inspect the SAML response

```php
use Oshco\Adfs\ADFSResponse;

$response = new ADFSResponse($_POST['SAMLResponse']);

$response->isSuccess();    // true if ADFS authentication succeeded
$response->getUserName();  // authenticated username (lowercased)
$response->getAppName();   // application name from ADFS
$response->getXMLString(); // raw XML of the SAML response
$response->storeResponse(); // save response to file for debugging
```

## Running Tests

```bash
composer test
```

## Maintainer

- Ibrahim BinAlshikh (i.binalshikh@oshco.com)

## License

This library is licensed under the [MIT License](LICENSE).

Copyright (c) 2023 Olayan Saudi Holding Company (OSHCO)
