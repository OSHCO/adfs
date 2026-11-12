<?php
namespace Oshco\Adfs;

use Exception;
use Throwable;

/**
 * Thrown when a SAML response cannot be parsed or fails validation.
 *
 * Every instance carries a machine-readable reason (one of the REASON_*
 * constants) that applications can log or map to a user-facing message.
 * The exception message is meant for logs and must not be shown to end users.
 */
class SAMLValidationException extends Exception {
    /** The response is not valid base64, is too large, or is not well-formed XML. */
    public const REASON_MALFORMED = 'malformed';
    /** The response contains a DOCTYPE declaration (blocked to prevent XXE). */
    public const REASON_DOCTYPE_NOT_ALLOWED = 'doctype_not_allowed';
    /** The status code of the response is not Success. */
    public const REASON_STATUS_NOT_SUCCESS = 'status_not_success';
    /** The response does not contain exactly one plain Assertion. */
    public const REASON_INVALID_ASSERTION_COUNT = 'invalid_assertion_count';
    /** The response contains an encrypted assertion, which is not supported. */
    public const REASON_ENCRYPTED_ASSERTION = 'encrypted_assertion';
    /** Two or more elements share the same ID attribute. */
    public const REASON_DUPLICATE_ID = 'duplicate_id';
    /** Neither the Response nor the Assertion carries a signature. */
    public const REASON_UNSIGNED = 'unsigned';
    /** A signature is present but does not verify against the configured certificates. */
    public const REASON_INVALID_SIGNATURE = 'invalid_signature';
    /** The signature uses an algorithm, transform or structure that is not allowed. */
    public const REASON_UNSUPPORTED_SIGNATURE = 'unsupported_signature';
    /** The assertion issuer does not match the expected issuer. */
    public const REASON_ISSUER_MISMATCH = 'issuer_mismatch';
    /** The assertion is not intended for the configured audience. */
    public const REASON_AUDIENCE_MISMATCH = 'audience_mismatch';
    /** The assertion is not yet valid (NotBefore is in the future). */
    public const REASON_NOT_YET_VALID = 'not_yet_valid';
    /** The assertion or its subject confirmation has expired. */
    public const REASON_EXPIRED = 'expired';
    /** No usable bearer subject confirmation was found. */
    public const REASON_INVALID_SUBJECT_CONFIRMATION = 'invalid_subject_confirmation';
    /** The subject confirmation recipient does not match the expected recipient. */
    public const REASON_RECIPIENT_MISMATCH = 'recipient_mismatch';
    /** InResponseTo on the Response does not match the one inside the assertion. */
    public const REASON_IN_RESPONSE_TO_MISMATCH = 'in_response_to_mismatch';
    /** The username attribute is missing from the assertion. */
    public const REASON_MISSING_USERNAME = 'missing_username';
    /** The application reported that the assertion was already used. */
    public const REASON_REPLAYED = 'replayed';

    private string $reason;

    /**
     * Creates new instance of the class.
     *
     * @param string $reason One of the REASON_* constants.
     * @param string $message A description of the problem for logs.
     * @param Throwable|null $previous The exception that caused this one, if any.
     */
    public function __construct(string $reason, string $message, ?Throwable $previous = null) {
        parent::__construct($message, 0, $previous);
        $this->reason = $reason;
    }

    /**
     * Returns the machine-readable reason of the failure.
     *
     * @return string One of the REASON_* constants.
     */
    public function getReason(): string {
        return $this->reason;
    }
}
