# IdentityModel Guidelines

## Overview

IdentityModel Extensions for .NET is a foundational authentication and authorization library that provides the core building blocks for implementing token-based security in .NET applications. The library specializes in:

- JSON Web Token (JWT) creation, validation, and management
- OpenID Connect (OIDC) and OAuth 2.0 protocol implementations
- Token validation and security key management
- High-performance token handling
- SAML token support
- WS-Federation protocol support

Through its robust architecture and battle-tested components, IdentityModel provides the security foundation used by numerous authentication libraries and frameworks, including Microsoft.Identity.Web and ASP.NET core authentication.

## Repository Structure

### Core Directories
- `/src` - Contains all source code for the Microsoft.IdentityModel packages
  - JsonWebTokens - Core JWT functionality
  - Protocols - Protocol implementations (OIDC, OAuth, WS-Fed)
  - Tokens - Token handling and validation
  - Xml - XML security functionality
  - Validators - Token validation components
- `/tests` - Unit tests, integration tests, and test utilities
- `/benchmark` - Performance benchmarking infrastructure
- `/build` - Build configuration and scripts

## Shipped Packages

### Core Token Handling
- Microsoft.IdentityModel.JsonWebTokens - JWT processing and validation
- Microsoft.IdentityModel.Tokens - Security token handling and validation
- System.IdentityModel.Tokens.Jwt - JWT framework for creating and validating JSON Web Tokens

### Protocol Support
- Microsoft.IdentityModel.Protocols - Base protocol handling infrastructure
- Microsoft.IdentityModel.Protocols.OpenIdConnect - OpenID Connect protocol implementation
- Microsoft.IdentityModel.Protocols.WsFederation - WS-Federation protocol support
- Microsoft.IdentityModel.Protocols.SignedHttpRequest - Signed HTTP request handling

### Security and Integration
- Microsoft.IdentityModel.Tokens.Saml - SAML token support
- Microsoft.IdentityModel.Xml - XML security functionality
- Microsoft.IdentityModel.Validators - Token validation utilities

## Development Guidelines

### Core Development Principles
- Follow .editorconfig rules strictly
- Prioritize performance in token handling operations
- Maintain backward compatibility due to widespread usage
- Implement thorough security validation
- Keep dependencies minimal and well-justified

### Performance Requirements
- Design for high-throughput token validation
- Optimize memory allocation patterns
- Consider token caching strategies
- Profile performance-critical paths
- Benchmark changes that affect token processing

### Security Guidelines
- Follow security best practices for cryptographic operations
- Validate all token parameters thoroughly
- Handle security keys with appropriate precautions
- Implement proper error handling for security operations
- Document security considerations for public APIs

### Testing Requirements
- Maintain comprehensive test coverage
- Include security validation tests
- Add performance benchmarks for critical paths
- Test with different key types and sizes
- Verify protocol compliance

### Public API Changes
- The project uses Microsoft.CodeAnalysis.PublicApiAnalyzers (version 3.3.4)
- For any public API changes:
  1. Update PublicAPI.Unshipped.txt in the relevant package directory
  2. Include complete API signatures
  3. Consider backward compatibility impacts
  4. Document breaking changes clearly

Example format:
```diff
// Adding new API
+Microsoft.IdentityModel.Tokens.TokenValidationResult.Clone() -> Microsoft.IdentityModel.Tokens.TokenValidationResult
+Microsoft.IdentityModel.Tokens.SecurityKey.KeySize.get -> int

// Removing API (requires careful consideration)
-Microsoft.IdentityModel.Tokens.ObsoleteTokenValidationMethod() -> void
```

The analyzer enforces documentation of all public API changes in PublicAPI.Unshipped.txt and will fail the build if changes are not properly reflected.
