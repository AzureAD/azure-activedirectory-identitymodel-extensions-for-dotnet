#Windows Azure Active Directory IdentityModel Extensions for .Net
===========

IdentityModel Extensions for .Net provide assemblies that are interesting for web developers that wish to use federated identity providers for establishing the callers identity. 

## Samples and Documentation

[We provide a full suite of sample applications and documentation on GitHub](https://github.com/AzureADSamples) to help you get started with learning the Azure Identity system. This includes tutorials for native clients such as Windows, Windows Phone, iOS, OSX, Android, and Linux. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect, Graph API, and other awesome features. 

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before. 

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Contributing

All code is licensed under the Apache 2.0 license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. See [CONTRIBUTING.md](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/master/CONTRIBUTING.md) for guidelines, branch information, build instructions, and legalese. 

## Assemblies in this repo
----

### System.IdentityModel.Tokens.Jwt

* Support for creating and validating Json Web Tokens.
* Provides model for config free validation using TokenValidationParameters.

### Microsoft.IdentityModel.Protocol.Extensions

* Support for creating and consuming OpenId and WsFederation messages.
* Support for validating Saml and Saml2 tokens using TokenValidationParameters.
* Support for dynamic metatdata retreival.

## License

Copyright (c) Microsoft Open Technologies, Inc.  All rights reserved. Licensed under the Apache License, Version 2.0 (the "License"); 
