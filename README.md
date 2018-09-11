Windows Azure Active Directory IdentityModel Extensions for .Net
===========

IdentityModel Extensions for .Net provide assemblies that are interesting for web developers that wish to use federated identity providers for establishing the callers identity. 

## Versions
Current version - 5.2.4
Minimum recommended version - 5.2.2

You can find the release notes for each version [here](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/wiki/Release-Notes).

## Security Vulnerability in Microsoft.IdentityModel.Tokens 5.1.0
IdentityModel Extensions library Microsoft.IdentityModel.Tokens has a known security vulnerability affecting version 5.1.0. Please update to >= 5.1.1 immediately. An updated package is available on NuGet. For more details, see the [security notice](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/master/SECURITY_NOTICE.md).

## Usage
IdentityModel Extensions for .NET 5 has now been released. If you are using IdentityModel Extensions with ASP.NET, the following combinations are supported:
* **IdentityModel Extensions for .NET 5.x**, **ASP.NET Core 1.x**, **ASP.NET Core 2.x**, **Katana 4.x**
* **IdentityModel Extensions for .NET 4.x**, **ASP.NET 4**, **Katana 3.x**
All other combinations aren't supported.

For more details see [Migration notes here](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/wiki/Migrating-from-Katana-(OWIN)-3.x-to-4.x)

## Samples and Documentation

The scenarios supported by IdentityModel extensions for .NET are described in [Scenarios](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/wiki/scenarios). The libraries are in particular used part of ASP.NET security to validate tokens in ASP.NET Web Apps and Web APIs. To learn more about token validation, and find samples, see:

- [Azure Active Directory with ASP.NET Core](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/azure-active-directory/?view=aspnetcore-2.1)
- [Developing ASP.NET Apps with Azure Active Directory](https://docs.microsoft.com/en-us/aspnet/identity/overview/getting-started/developing-aspnet-apps-with-windows-azure-active-directory)
- [Validating tokens](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/wiki/ValidatingTokens)
- more generally, the librarie's [Wiki](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/wiki)
- the [reference documentation](https://docs.microsoft.com/en-us/dotnet/api/overview/azure/activedirectory/client?view=azure-dotnet) 



## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browse existing issues to see if someone has had your question before. 

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Security Reporting

If you find a security issue with our libraries or services please report it to [secure@microsoft.com](mailto:secure@microsoft.com) with as much detail as possible. Your submission may be eligible for a bounty through the [Microsoft Bounty](http://aka.ms/bugbounty) program. Please do not post security issues to GitHub Issues or any other public site. We will contact you shortly upon receiving the information. We encourage you to get notifications of when security incidents occur by visiting [this page](https://technet.microsoft.com/en-us/security/dd252948) and subscribing to Security Advisory Alerts.

## Contributing

All code is licensed under the MIT license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. See [Contributing.md](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/master/Contributing.md) for guidelines, branch information, build instructions, and legalese. 


## License

Copyright (c) Microsoft Corporation.  All rights reserved. Licensed under the MIT License (the "License"); 

## We Value and Adhere to the Microsoft Open Source Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

