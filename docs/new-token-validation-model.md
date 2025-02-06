# New token validation model
The existing token validation model on `Microsoft.IdentityModel` relies on the exception based control flow dominant in C#. In some high-performance scenarios where latency is key, this can cause unintended increases when validations fail and throw.  

As part of an effort to modernize aspects of the library that have become bloated over the years, we are introducing an alternative token validation model that breaks away from some of the previous behaviors and intends to offer a slimmer and more performant API.  

## Key points on the new model
- Performance increase by removing unnecessary exception throwing within the validation itself.
- Return a result where it is clear whether the validation was successful, including relevant information depending on the case.
  - In success scenarios, provide the validated information for audit purposes.
  - In failure scenarios, provide enough information to identify what part of the token was invalid or could not be validated without the need for further steps, and for diagnostic purposes provide the ability to create an exception that can be thrown and observed. 
- Do not automatically print logs as part of the validation. These can be printed from the validation result using C#'s [high-performance logging](https://learn.microsoft.com/en-us/dotnet/core/extensions/high-performance-logging) based on `ILogger`.
- Simpler validation parameters object, as the current one has grown in complexity over the years by including multiple parameters for things like `ValidIssuer` and `ValidIssuers`, or multiple delegates for the same validation. `ValidationParameters` is being introduced as an alternative to `TokenValidationParameters`, to offer a clearer configuration object that enables simplifying the default validation code as well.
- New APIs provide nullability annotations to simplify code branches when the API can ensure no `null` will be returned from a method.
- New async APIs receive a `CancellationToken` to allow for the cancellation of running validation operations, as expected.

## Embracing the Result pattern to remove exceptions on a hot path
In order to remove the exceptions being thrown, we are introducing a `ValidationResult` type to handle the result of all validation operations.  
This type can be thought of as a **one of** type as `ValidationResult<TResult, TError>`, though the `TError` type is initially being fixed to `ValidationError`.  

The `ValidationResult` object can only be created in one of two ways:
- As a success object, where `TResult` is provided.
- As a failure object, where `TError` (`ValidationError`) is provided. These two can never exist at the same time on an instance of this object.  

The `IsValid` property of `ValidationResult` reflects which of these two scenarios is the current.

The following example attempts to illustrate this:

### Creating a ValidationResult
```csharp
// ValidationResult<TResult> can contain TResult if valid, or ValidationError if not.

ValidationResult<string> issuerValidationResult = "some-issuer"; // valid, creates a successful result with "some-issuer" as the Result
issuerValidationResult.IsValid // true
issuerValidationResult.Result // "some-issuer"
issuerValidationResult.Error // null

ValidationResult<string> issuerValidationResult2 = new IssuerValidationError(...) // valid, creates a failed result with the new instance of IssuerValidationError as the Error, which inherits from ValidationError and adds extra information such as the invalid issuer
issuerValidationResult2.IsValid // false
issuerValidationResult2.Result // null
issuerValidationResult2.Error // the IssuerValidationError instance
```

### Validating a token using the new validation model
During the initial preview, the new validation methods are not exposed publicly in `JsonWebTokenHandler`, `SamlSecurityTokenHandler`, or `Saml2SecurityTokenHandler`, but can be accessed via the experimental interface `IResultBasedValidation` which all 3 explicitly implement.
```csharp
string token = "some JWT token";
ValidationParameters validationParameters = new ValidationParameters()
{
    ValidAudiences = ["http://Default.Audience.com"],
    ValidIssuers = ["http://Default.Issuer.com"],
    IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
};
CallContext callContext = new CallContext();

JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
ValidationResult<ValidatedToken> validationResult = await ((IResultBasedValidation)jsonWebTokenHandler).ValidateTokenAsync(token, validationParameters, callContext, default);

if (validationResult.IsValid)
    // do something with the ValidatedToken returned.
    ValidatedToken validatedToken = validationResult.Result;
else
    // inspect the error, log it to telemetry, etc
    ValidationError validationError = validationResult.Error;
```

Examples of this can be found in [dev/test/Microsoft.IdentityModel.JsonWebTokens.Tests/JsonWebTokenHandler.ValidateTokenAsyncTests_e2e.cs](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/dev/test/Microsoft.IdentityModel.JsonWebTokens.Tests/JsonWebTokenHandler.ValidateTokenAsyncTests_e2e.cs).

### Benchmarks
```
| Method                                                                     | Mean       | Error      | StdDev     | Median     | P95       | P90       | P100      | Ratio | RatioSD | Gen0   | Gen1   | Allocated | Alloc Ratio |
|--------------------------------------------------------------------------- |-----------:|-----------:|-----------:|-----------:|----------:|----------:|----------:|------:|--------:|-------:|-------:|----------:|------------:|
| JsonWebTokenHandler_ValidateTokenAsyncCurrentModel_Success                 |  42.049 us |  1.2346 us |  2.7614 us |  42.673 us |  44.91 us |  44.73 us |  46.52 us |  1.00 |    0.00 | 0.7629 |      - |   7.23 KB |        1.00 |
| JsonWebTokenHandler_ValidateTokenAsyncNewModel_Success                     |  41.554 us |  1.2499 us |  2.7698 us |  42.213 us |  44.52 us |  44.30 us |  45.89 us |  0.99 |    0.10 | 0.7019 |      - |   6.72 KB |        0.93 |
|                                                                            |            |            |            |            |           |           |           |       |         |        |        |           |             |
| JsonWebTokenHandler_ValidateTokenAsyncCurrentModel_Failure                 |  22.134 us |  0.5585 us |  1.2259 us |  22.555 us |  23.30 us |  23.26 us |  23.57 us |     ? |       ? | 0.8545 | 0.0153 |   7.91 KB |           ? |
| JsonWebTokenHandler_ValidateTokenAsyncNewModel_Failure                     |   9.797 us |  0.2967 us |  0.6450 us |   9.915 us |  10.44 us |  10.37 us |  10.50 us |     ? |       ? | 0.8392 | 0.0153 |   7.78 KB |           ? |
|                                                                            |            |            |            |            |           |           |           |       |         |        |        |           |             |
| JsonWebTokenHandler_ValidateTokenAsyncCurrentModel_CreateClaims            |  24.184 us |  0.4497 us |  0.9776 us |  24.039 us |  25.80 us |  25.35 us |  26.84 us |  1.00 |    0.00 | 1.7700 | 0.0610 |  16.49 KB |        1.00 |
| JsonWebTokenHandler_ValidateTokenAsyncNewModel_CreateClaims                |  22.486 us |  0.0768 us |  0.1669 us |  22.513 us |  22.74 us |  22.70 us |  22.77 us |  0.93 |    0.04 | 1.7395 | 0.0610 |  16.05 KB |        0.97 |
|                                                                            |            |            |            |            |           |           |           |       |         |        |        |           |             |
| JsonWebTokenHandler_ValidateTokenAsyncCurrentModel_SucceedOnThirdAttempt   |  90.089 us | 12.4752 us | 26.8542 us |  92.713 us | 142.90 us | 105.99 us | 173.30 us |  1.00 |    0.00 | 2.3804 |      - |  22.18 KB |        1.00 |
| JsonWebTokenHandler_ValidateTokenAsyncNewModel_SucceedOnThirdAttempt       |  58.293 us |  4.0626 us |  9.0866 us |  61.416 us |  65.48 us |  64.87 us |  65.72 us |  0.71 |    0.30 | 2.3804 |      - |  22.28 KB |        1.00 |
|                                                                            |            |            |            |            |           |           |           |       |         |        |        |           |             |
| JsonWebTokenHandler_ValidateTokenAsyncCurrentModel_SucceedOnFifthAttempt   |  69.650 us |  9.0710 us | 19.3311 us |  62.202 us | 128.34 us |  79.92 us | 143.15 us |  1.00 |    0.00 | 3.9063 |      - |  37.13 KB |        1.00 |
| JsonWebTokenHandler_ValidateTokenAsyncNewModel_SucceedOnFifthAttempt       |  82.433 us |  2.1832 us |  4.7461 us |  83.732 us |  87.97 us |  86.24 us |  89.80 us |  1.24 |    0.21 | 4.0894 | 0.0610 |  37.84 KB |        1.02 |
```