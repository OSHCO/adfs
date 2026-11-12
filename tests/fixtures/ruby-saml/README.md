# ruby-saml ADFS fixtures

ADFS-format SAML responses copied unchanged from
[SAML-Toolkits/ruby-saml](https://github.com/SAML-Toolkits/ruby-saml)
(`test/responses/`, commit `7c7dccd3c18768e54b6fc56522d6d5d8dfb79bd8`), under the
MIT license in `LICENSE`.

They are signed by a different implementation than xmlseclibs, so they check that
the validator works with signatures it did not produce itself.

Quirks of these files:

- `X509Certificate` holds base64 of a PEM file instead of base64 of DER, so the
  test decodes it once before use. Real ADFS responses hold DER.
- They have no attribute statement, so a valid one stops at the last check,
  `missing_username`, after all signature and condition checks passed.
- The SHA-1 and SHA-384 samples from the same folder are not included: they use
  algorithm URIs that are not in the XML-DSig or XML-Enc specifications.
