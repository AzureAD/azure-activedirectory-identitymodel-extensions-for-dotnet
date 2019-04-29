//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Data sets for testing 
/// </summary>
namespace Microsoft.IdentityModel.TestUtils
{
    public class DataSets
    {
        public static JsonWebKey JsonWebKeyFromPing1;
        public static JsonWebKey JsonWebKeyFromPing2;
        public static JsonWebKey JsonWebKeyFromPing3;
        public static JsonWebKey JsonWebKey1;
        public static JsonWebKey JsonWebKey2;
        public static JsonWebKey JsonWebKeyAdditionalData1;
        public static JsonWebKey JsonWebKeyBadX509Data;
        public static JsonWebKey JsonWebKeyES256;
        public static JsonWebKey JsonWebKeyES384;
        public static JsonWebKey JsonWebKeyES512;

        public static JsonWebKeySet JsonWebKeySet1;
        public static JsonWebKeySet JsonWebKeySet2;
        public static JsonWebKeySet JsonWebKeySetX509Data;
        public static JsonWebKeySet JsonWebKeySetAdditionalData1;
        public static JsonWebKeySet JsonWebKeySetEC;

        // interop
        public static string GoogleCertsFile = "google-certs.json";
        public static JsonWebKeySet GoogleCertsExpected;

        public static string JsonWebKey_X5c_1 = "MIIDPjCCAiqgAwIBAgIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTIwNjA3MDcwMDAwWhcNMTQwNjA3MDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVwIDAQABo2IwYDBeBgNVHQEEVzBVgBCxDDsLd8xkfOLKm4Q/SzjtoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAA4IBAQAkJtxxm/ErgySlNk69+1odTMP8Oy6L0H17z7XGG3w4TqvTUSWaxD4hSFJ0e7mHLQLQD7oV/erACXwSZn2pMoZ89MBDjOMQA+e6QzGB7jmSzPTNmQgMLA8fWCfqPrz6zgH+1F1gNp8hJY57kfeVPBiyjuBmlTEBsBlzolY9dd/55qqfQk6cgSeCbHCy/RU/iep0+UsRMlSgPNNmqhj5gmN2AFVCN96zF694LwuPae5CeR2ZcVknexOWHYjFM0MgUSw0ubnGl0h9AJgGyhvNGcjQqu9vd1xkupFgaN+f7P3p3EVN5csBg5H94jEcQZT7EKeTiZ6bTrpDAnrr8tDCy8ng";
        public static string JsonWebKey_X5c_2 = "MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ";

        public static string JsonWebKeyFromPingString1 =
                                        @"{ ""e"":""AQAB"",
                                            ""kid"":""20am7"",
                                            ""kty"":""RSA"",
                                            ""n"":""mhupHfUtg_gHIqwu2wm8CprXY-gKqbPMV6tEYVqkyYrHugzQ_YDYAHr7vWo5Pe_3gIujSFwpqIfXaP8-Fl3O5fQhMo1lMv4DdRabyDLEpv7YO9qoVKTmDOZqYZx-AYBr5x1Zh2xWByI6_0dsPtCjD1pFZfg_SxNEcLPyH1aY6dT8CWYu32qG4O0WF4EihZzMkzSn8fyh8RXbMf5U9Wm2kgb0g8jK62S7MoF4IlhFaJreq898wgUohhPwR8P3X-gk0XQJAFcogEf04Fw4UmKo3z1B6mcNbPRfImhWw4wtLkhp_KIqKNOkMsSpYGSLrCvqQpgK56EJZExrmb7WozjwHw"",
                                            ""use"":""sig""
                                        }";

        public static string JsonWebKeyString1 =
                                        @"{ ""alg"":""SHA256"",
                                            ""e"":""AQAB"",
                                            ""key_ops"":[""signing""],
                                            ""kid"":""NGTFvdK-fythEuLwjpwAJOM9n-A"",
                                            ""kty"":""RSA"",                                            
                                            ""n"":""rCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVw=="",                                            
                                            ""x5c"":[""MIIDPjCCAiqgAwIBAgIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTIwNjA3MDcwMDAwWhcNMTQwNjA3MDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVwIDAQABo2IwYDBeBgNVHQEEVzBVgBCxDDsLd8xkfOLKm4Q/SzjtoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAA4IBAQAkJtxxm/ErgySlNk69+1odTMP8Oy6L0H17z7XGG3w4TqvTUSWaxD4hSFJ0e7mHLQLQD7oV/erACXwSZn2pMoZ89MBDjOMQA+e6QzGB7jmSzPTNmQgMLA8fWCfqPrz6zgH+1F1gNp8hJY57kfeVPBiyjuBmlTEBsBlzolY9dd/55qqfQk6cgSeCbHCy/RU/iep0+UsRMlSgPNNmqhj5gmN2AFVCN96zF694LwuPae5CeR2ZcVknexOWHYjFM0MgUSw0ubnGl0h9AJgGyhvNGcjQqu9vd1xkupFgaN+f7P3p3EVN5csBg5H94jEcQZT7EKeTiZ6bTrpDAnrr8tDCy8ng""],
                                            ""x5t"":""NGTFvdK-fythEuLwjpwAJOM9n-A"",
                                            ""x5u"":""https://jsonkeyurl"",
                                            ""use"":""sig""
                                        }";

        public static string JsonWebKeyString2 =
                                        @"{ ""alg"":""SHA256"",
                                            ""e"":""AQAB"",
                                            ""kid"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""kty"":""RSA"",
                                            ""n"":""kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw=="",
                                            ""x5t"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""x5c"":[""MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ""],
                                            ""use"":""sig""
                                        }";

        public static string JsonWebKeyAdditionalDataString1 =
                                        @"{ ""alg"":""SHA256"",
                                            ""e"":""AQAB"",
                                            ""kid"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""kty"":""RSA"",
                                            ""n"":""kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw=="",
                                            ""x5t"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""x5c"":[""MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ""],
                                            ""use"":""sig"",
                                            ""additionalProperty"":""additionalValue""
                                        }";

        public static string JsonWebKeyBadFormatString1 =
                                        @"{ ""e"":""AQAB"",
                                            ""kid"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""kty"":""RSA"",
                                            ""n"":""kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw=="",                                                                                                                                            
                                            ""x5c"":[""MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ""],
                                            ""x5t"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""use""::""sig""
                                            }";

        public static string JsonWebKeyBadFormatString2 =
                                        @"{ ""e"":""AQAB"",
                                            ""kid"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""kty"":""RSA"",
                                            ""n"":""kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw=="",
                                            ""x5c"":""M""IIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ""],
                                            ""x5t"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""use""::""sig""
                                            }";

        public static string JsonWebKeyBadRsaExponentString =
                                        @"{ ""e"":""AQABC"",
                                            ""kid"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""kty"":""RSA"",
                                            ""n"":""kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw=="",                                               
                                            ""use"":""sig""
                                        }";

        public static string JsonWebKeyBadRsaModulusString =
                                        @"{ ""e"":""AQAB"",
                                            ""kid"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""kty"":""RSA"",
                                            ""n"":""kSSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw=="",                                               
                                            ""use"":""sig""
                                        }";

        public static string JsonWebKeyRsaNoKidString =
                                        @"{ ""e"":""AQAB"",
                                            ""kty"":""RSA"",
                                            ""n"":""kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw=="",                                               
                                            ""use"":""sig""
                                        }";

        public static string JsonWebKeyKtyNotRsaString =
                                        @"{ ""e"":""AQAB"",
                                            ""kid"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""kty"":""RSAA"",
                                            ""n"":""kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw=="",                                               
                                            ""use"":""sig""
                                        }";

        public static string JsonWebKeyUseNotSigString =
                                        @"{ ""e"":""AQAB"",
                                            ""kid"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""kty"":""RSA"",
                                            ""n"":""kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw=="",                                               
                                            ""use"":""sigg""
                                        }";

        public static string JsonWebKeyBadX509String =
                                        @"{ ""e"":""AQAB"",
                                            ""kid"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""kty"":""RSA"",
                                            ""n"":""kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw=="",
                                            ""x5c"":[""==MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ""],
                                            ""x5t"":""kriMPdmBvx68skT8-mPAB3BseeA"",
                                            ""use"":""sig""
                                        }";

        public static string JsonWebKeyBadECCurveString =
                                       @"{
                                            ""kty"": ""EC"",
                                            ""alg"": ""ES521"",
                                            ""use"": ""sig"",
                                            ""crv"": ""P-999"",
                                            ""kid"": ""unknownCrv"",
                                            ""x"": ""AX0BXx6mpDjvGk-NLTwobKNjfAP4QCRjtKi8UQsuPqQ2sRKITAcSti3UMn0COcrG_FVgEDNPyPVlSi5LnUl0dREr"",
                                            ""y"": ""AZ8DlNxsA6eCj_JL9Rz8uU4eacd-XX--ek8-VCOgv3YNRPeN_2PJauJL7q9Pg1MSe8zEaLIRhM4SGWJ4SI1rMhlW""
                                        }";

        public static string JsonWebKeyES256String =
                                        @"{
                                            ""kty"": ""EC"",
                                            ""alg"": ""ES256"",
                                            ""use"": ""sig"",
                                            ""crv"": ""P-256"",
                                            ""kid"": ""JsonWebKeyEcdsa256"",
                                            ""x"": ""luR290c8sXxbOGhNquQ3J3rh763Os4D609cHK-L_5fA"",
                                            ""y"": ""tUqUwtaVHwc7_CXnuBrCpMQTF5BJKdFnw9_JkSIXWpQ""
                                        }";

        public static string JsonWebKeyES384String =
                                        @"{
                                            ""kty"": ""EC"",
                                            ""alg"": ""ES384"",
                                            ""use"": ""sig"",
                                            ""crv"": ""P-384"",
                                            ""kid"": ""JsonWebKeyEcdsa384"",
                                            ""x"": ""5mn3HaDoUgdNTFCACaWIvrpriQTloEbMbx4eUu_XvB4pyExig45VIozMnj7FedJg"",
                                            ""y"": ""Vh872HVKNHrzlVu0Ko-3dN-eHoDYBeZgdGLAqenyZ0_X_TctwT6MVLxcAvwbJG5l""
                                        }";

        public static string JsonWebKeyES512String =
                                        @"{
                                            ""kty"": ""EC"",
                                            ""alg"": ""ES512"",
                                            ""use"": ""sig"",
                                            ""crv"": ""P-521"",
                                            ""kid"": ""JsonWebKeyEcdsa521"",
                                            ""x"": ""AX0BXx6mpDjvGk-NLTwobKNjfAP4QCRjtKi8UQsuPqQ2sRKITAcSti3UMn0COcrG_FVgEDNPyPVlSi5LnUl0dREr"",
                                            ""y"": ""AZ8DlNxsA6eCj_JL9Rz8uU4eacd-XX--ek8-VCOgv3YNRPeN_2PJauJL7q9Pg1MSe8zEaLIRhM4SGWJ4SI1rMhlW""
                                        }";

        public static string JsonWebKeySetBadRsaExponentString = @"{ ""keys"":[" + JsonWebKeyBadRsaExponentString + "]}";
        public static string JsonWebKeySetBadRsaModulusString = @"{ ""keys"":[" + JsonWebKeyBadRsaModulusString + "]}";
        public static string JsonWebKeySetUseNoKidString = @"{ ""keys"":[" + JsonWebKeyRsaNoKidString + "]}";
        public static string JsonWebKeySetKtyNotRsaString = @"{ ""keys"":[" + JsonWebKeyKtyNotRsaString + "]}";
        public static string JsonWebKeySetUseNotSigString = @"{ ""keys"":[" + JsonWebKeyUseNotSigString + "]}";
        public static string JsonWebKeySetBadX509String = @"{ ""keys"":[" + JsonWebKeyBadX509String + "]}";
        public static string JsonWebKeySetBadECCurveString = @"{ ""keys"":[" + JsonWebKeyBadECCurveString + "]}";

        // Key Sets
        public static string JsonWebKeySet = "JsonWebKeySet.json";
        public static string JsonWebKeySetString1 = @"{ ""keys"":[" + JsonWebKeyString1 + "," + JsonWebKeyString2 + "]}";
        public static string JsonWebKeySetString2 = @"{ ""keys"":[" + JsonWebKeyString2 + "]}";
        public static string JsonWebKeySetECCString = @"{ ""keys"":[" + JsonWebKeyES256String + "," + JsonWebKeyES384String + "," + JsonWebKeyES512String + "]}";
        public static string JsonWebKeySetAdditionalDataString1 = @"{ ""keys"":[" + JsonWebKeyAdditionalDataString1 + "]" + @", ""additionalProperty"":""additionalValue""}";
        public static string JsonWebKeySetBadFormatingString =
                                            @"{ ""keys"":[
                                                {   ""e"":""AQAB"",
                                                    ""kid"":""NGTFvdK-fythEuLwjpwAJOM9n-A"",
                                                    ""kty"":""RSA"",
                                                    ""n"":""rCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVw=="",
                                                    ""x5c"":[""MIIDPjCCAiqgAwIBAgIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTIwNjA3MDcwMDAwWhcNMTQwNjA3MDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVwIDAQABo2IwYDBeBgNVHQEEVzBVgBCxDDsLd8xkfOLKm4Q/SzjtoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAA4IBAQAkJtxxm/ErgySlNk69+1odTMP8Oy6L0H17z7XGG3w4TqvTUSWaxD4hSFJ0e7mHLQLQD7oV/erACXwSZn2pMoZ89MBDjOMQA+e6QzGB7jmSzPTNmQgMLA8fWCfqPrz6zgH+1F1gNp8hJY57kfeVPBiyjuBmlTEBsBlzolY9dd/55qqfQk6cgSeCbHCy/RU/iep0+UsRMlSgPNNmqhj5gmN2AFVCN96zF694LwuPae5CeR2ZcVknexOWHYjFM0MgUSw0ubnGl0h9AJgGyhvNGcjQqu9vd1xkupFgaN+f7P3p3EVN5csBg5H94jEcQZT7EKeTiZ6bTrpDAnrr8tDCy8ng""
                                                    ""x5t"":""NGTFvdK-fythEuLwjpwAJOM9n-A"",
                                                    ""use"":""sig""
                                                }
                                            ]}";

        public static string JsonWebKeySetSingleX509DataString =
                                            @"{ ""keys"":[
                                                {   ""e"":""AQAB"",                                                                                                
                                                    ""kid"":""NGTFvdK-fythEuLwjpwAJOM9n-A"",                                               
                                                    ""kty"":""RSA"",
                                                    ""n"":""rCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVw=="",
                                                    ""x5c"":""MIIDPjCCAiqgAwIBAgIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTIwNjA3MDcwMDAwWhcNMTQwNjA3MDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVwIDAQABo2IwYDBeBgNVHQEEVzBVgBCxDDsLd8xkfOLKm4Q/SzjtoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAA4IBAQAkJtxxm/ErgySlNk69+1odTMP8Oy6L0H17z7XGG3w4TqvTUSWaxD4hSFJ0e7mHLQLQD7oV/erACXwSZn2pMoZ89MBDjOMQA+e6QzGB7jmSzPTNmQgMLA8fWCfqPrz6zgH+1F1gNp8hJY57kfeVPBiyjuBmlTEBsBlzolY9dd/55qqfQk6cgSeCbHCy/RU/iep0+UsRMlSgPNNmqhj5gmN2AFVCN96zF694LwuPae5CeR2ZcVknexOWHYjFM0MgUSw0ubnGl0h9AJgGyhvNGcjQqu9vd1xkupFgaN+f7P3p3EVN5csBg5H94jEcQZT7EKeTiZ6bTrpDAnrr8tDCy8ng"",
                                                    ""x5t"":""NGTFvdK-fythEuLwjpwAJOM9n-A"",
                                                    ""use"":""sig""
                                               }
                                            ]}";

        static DataSets()
        {
            JsonWebKeyFromPing1 = new JsonWebKey
            {
                E = "AQAB",
                Kid = "20am7",
                Kty = "RSA",
                N = "mhupHfUtg_gHIqwu2wm8CprXY-gKqbPMV6tEYVqkyYrHugzQ_YDYAHr7vWo5Pe_3gIujSFwpqIfXaP8-Fl3O5fQhMo1lMv4DdRabyDLEpv7YO9qoVKTmDOZqYZx-AYBr5x1Zh2xWByI6_0dsPtCjD1pFZfg_SxNEcLPyH1aY6dT8CWYu32qG4O0WF4EihZzMkzSn8fyh8RXbMf5U9Wm2kgb0g8jK62S7MoF4IlhFaJreq898wgUohhPwR8P3X-gk0XQJAFcogEf04Fw4UmKo3z1B6mcNbPRfImhWw4wtLkhp_KIqKNOkMsSpYGSLrCvqQpgK56EJZExrmb7WozjwHw",
                Use = "sig"
            };

            JsonWebKeyFromPing2 = new JsonWebKey
            {
                E = "AQAB",
                Kid = "20am3",
                Kty = "RSA",
                N = "wY2KNRyiEvyBFkr1IC_1UGWMPInkzVYpoap_-Zw5fYAXLVxKMSPdZVVLt9AVhuNtagOOQqlZ_Y32e4l19REHym6RGV9Sm1noKRxDUjkz7U8OVeUew7D7h4Dk6E2rrlIYpy9OmhhzWSS68pBTf0_ESdekKv3OQbEs99avEXOPK5uH3V-NHsy1YP3DAvl7HJaV6fn-1Nch1quLrg1G7ohBuTb4Zr-499TJ6bkfabaACz8bf-RHuPezFBjoY0LHNNu6-KQ-qqHVkoki_1OQwj2s_Lui3qYWOmLoaVN9ZzO90rBdhhg8t0JZv6pSlc7o0XT4fie5RRjiqCuOpuGQvNYKpQ",
                Use = "sig"
            };

            JsonWebKeyFromPing3 = new JsonWebKey
            {
                E = "AQAB",
                Kid = "20alz",
                Kty = "RSA",
                N = "tgLZUXY8mo2Y1TaXHjOYrFGs23jZxgpzEKfBz004AEeOMHFbEP1h1Lrqf2B7f49mOpXRkBgEm4tnSYzX7pDWrMvNeRVkTFXSXwHYvda1R1kmwiTxnrC9IWjvizrr22DtzHhSSpL_7xuXtmaid2orOF8mUoXnKesPQVfq33pCKm1QUV6oFNSVxAiOKJkzFmxjYvcqzryjYi10glxPSx3cmSI8RGqlxolJr0negfLmI9bNxuAvStf_L6zXB5NFqccmkCQXn_QC3P1N3j-HgwwHTVFxkrS8kZQOMTw3TMXbtTFNrVAx1QC_3M0ze4cVncr2zTSECS_2qXM5RS7xBTEDvQ",
                Use = "sig"
            };

            JsonWebKey1 = new JsonWebKey
            {
                Alg = "SHA256",
                E = "AQAB",
                Kid = "NGTFvdK-fythEuLwjpwAJOM9n-A",
                Kty = "RSA",
                N = "rCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVw==",
                X5t = "NGTFvdK-fythEuLwjpwAJOM9n-A",
                X5u = "https://jsonkeyurl",
                Use = "sig",
            };

            JsonWebKey1.X5c.Add(JsonWebKey_X5c_1);
            JsonWebKey1.KeyOps.Add("signing");
            JsonWebKey2 = new JsonWebKey
            {
                Alg = "SHA256",
                E = "AQAB",
                Kid = "kriMPdmBvx68skT8-mPAB3BseeA",
                Kty = "RSA",
                N = "kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw==",
                X5t = "kriMPdmBvx68skT8-mPAB3BseeA",
                Use = "sig",
            };

            JsonWebKey2.X5c.Add(JsonWebKey_X5c_2);

            JsonWebKeyES256 = new JsonWebKey
            {
                Alg = "ES256",
                Crv = "P-256",
                Kid = "JsonWebKeyEcdsa256",
                Kty = "EC",
                Use = "sig",
                X = "luR290c8sXxbOGhNquQ3J3rh763Os4D609cHK-L_5fA",
                Y = "tUqUwtaVHwc7_CXnuBrCpMQTF5BJKdFnw9_JkSIXWpQ"
            };

            JsonWebKeyES384 = new JsonWebKey
            {
                Alg = "ES384",
                Crv = "P-384",
                Kid = "JsonWebKeyEcdsa384",
                Kty = "EC",
                Use = "sig",
                X = "5mn3HaDoUgdNTFCACaWIvrpriQTloEbMbx4eUu_XvB4pyExig45VIozMnj7FedJg",
                Y = "Vh872HVKNHrzlVu0Ko-3dN-eHoDYBeZgdGLAqenyZ0_X_TctwT6MVLxcAvwbJG5l"
            };

            JsonWebKeyES512 = new JsonWebKey
            {
                Alg = "ES512",
                Crv = "P-521",
                Kid = "JsonWebKeyEcdsa521",
                Kty = "EC",
                Use = "sig",
                X = "AX0BXx6mpDjvGk-NLTwobKNjfAP4QCRjtKi8UQsuPqQ2sRKITAcSti3UMn0COcrG_FVgEDNPyPVlSi5LnUl0dREr",
                Y = "AZ8DlNxsA6eCj_JL9Rz8uU4eacd-XX--ek8-VCOgv3YNRPeN_2PJauJL7q9Pg1MSe8zEaLIRhM4SGWJ4SI1rMhlW"
            };

            JsonWebKeySet1 = new JsonWebKeySet();
            JsonWebKeySet1.Keys.Add(JsonWebKey1);
            JsonWebKeySet1.Keys.Add(JsonWebKey2);

            JsonWebKeySetEC = new JsonWebKeySet();
            JsonWebKeySetEC.Keys.Add(JsonWebKeyES256);
            JsonWebKeySetEC.Keys.Add(JsonWebKeyES384);
            JsonWebKeySetEC.Keys.Add(JsonWebKeyES512);

            var jwk = new JsonWebKey
            {
                Kid = "NGTFvdK-fythEuLwjpwAJOM9n-A",
                Kty = "RSA",
                Use = "sig",
                X5t = "NGTFvdK-fythEuLwjpwAJOM9n-A"
            };

            jwk.X5c.Add("MIIDPjCCAiqgAwIBAgIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTIwNjA3MDcwMDAwWhcNMTQwNjA3MDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVwIDAQABo2IwYDBeBgNVHQEEVzBVgBCxDDsLd8xkfOLKm4Q/SzjtoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAA4IBAQAkJtxxm/ErgySlNk69+1odTMP8Oy6L0H17z7XGG3w4TqvTUSWaxD4hSFJ0e7mHLQLQD7oV/erACXwSZn2pMoZ89MBDjOMQA+e6QzGB7jmSzPTNmQgMLA8fWCfqPrz6zgH+1F1gNp8hJY57kfeVPBiyjuBmlTEBsBlzolY9dd/55qqfQk6cgSeCbHCy/RU/iep0+UsRMlSgPNNmqhj5gmN2AFVCN96zF694LwuPae5CeR2ZcVknexOWHYjFM0MgUSw0ubnGl0h9AJgGyhvNGcjQqu9vd1xkupFgaN+f7P3p3EVN5csBg5H94jEcQZT7EKeTiZ6bTrpDAnrr8tDCy8ng");

            JsonWebKeySetX509Data = new JsonWebKeySet();
            JsonWebKeySetX509Data.Keys.Add(jwk);

            JsonWebKeyAdditionalData1 = new JsonWebKey
            {
                Alg = "SHA256",
                E = "AQAB",
                Kid = "kriMPdmBvx68skT8-mPAB3BseeA",
                Kty = "RSA",
                N = "kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw==",
                X5t = "kriMPdmBvx68skT8-mPAB3BseeA",
                Use = "sig",
            };

            JsonWebKeyAdditionalData1.AdditionalData["additionalProperty"] = "additionalValue";
            JsonWebKeyAdditionalData1.X5c.Add(JsonWebKey_X5c_2);
            JsonWebKeySetAdditionalData1 = new JsonWebKeySet();
            JsonWebKeySetAdditionalData1.Keys.Add(JsonWebKeyAdditionalData1);
            JsonWebKeySetAdditionalData1.AdditionalData["additionalProperty"] = "additionalValue";

            JsonWebKeyBadX509Data = new JsonWebKey
            {
                E = "AQAB",
                Kid = "kriMPdmBvx68skT8-mPAB3BseeA",
                Kty = "RSA",
                N = "kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw==",
                X5t = "kriMPdmBvx68skT8-mPAB3BseeA",
                Use = "sig"
            };

            JsonWebKeyBadX509Data.X5c.Add("==MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ");

            GoogleCertsExpected = new JsonWebKeySet();
            GoogleCertsExpected.Keys.Add(
                new JsonWebKey
                {
                    Alg = "RS256",
                    E = "AQAB",
                    Kty = "RSA",
                    Kid = "ab844f3d4c69feee0de2501b04e1a4c8d78eead1",
                    N = "AKrMiv5vhYehVKXnSpZZN6lYymUIi+NS97ceYKYClMlNyj2Ln4ErWiOwjwdivG2kZnN0kKCC/XL9E+uEgsZO3ECvvDtgtFhPOR0MiqL7pp/K7d58dbKUWX/cWy8E4bm/Zmwa/g0HDcW6o19+Q85IPYXbY/6Z2oOgA9qDAoGHkjIv",
                    Use = "sig",
                });

            GoogleCertsExpected.Keys.Add(
                 new JsonWebKey
                 {
                     Alg = "RS256",
                     E = "AQAB",
                     Kty = "RSA",
                     Kid = "550326e0aacb4674d22905a1a51a808cfa7463b0",
                     N = "ANLFuJO6EoKczde+YP3b1yuz2b46D7Rd7CjrbvKrzbjkH29iRFLBagT7nojwdMOPrsV+WLp/C8lfkRT7UJ38lnQh3m4oEy98HdRRMZh5Vtpbotgt4S/ugh5ansJdHSXSBTxk+X1ZnTzMOUH7ZROpxw3NcX/IFl0sshFlTbebPrDj",
                     Use = "sig",
                 });
        }
    }
}
