// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.Extensions.Logging;

namespace Microsoft.IdentityModel.Validators;

internal static partial class LoggerExtensions
{
#if NET6_0_OR_GREATER
    [LoggerMessage(
        EventId = 40001,
        Level = LogLevel.Error,
        Message = "IDX40001: Issuer: '{issuer}', does not match any of the valid issuers provided for this application. ")]
    public static partial void NoValidIssuerMatch(this ILogger logger, string issuer);

    [LoggerMessage(
        EventId = 40002,
        Level = LogLevel.Error,
        Message = "IDX40002: Microsoft.IdentityModel does not support a B2C issuer with 'tfp' in the URI. See https://aka.ms/ms-id-web/b2c-issuer for details. ")]
    public static partial void UnsupportedB2CIssuer(this ILogger logger);

    [LoggerMessage(
        EventId = 40003,
        Level = LogLevel.Error,
        Message = "IDX40003: Neither `tid` nor `tenantId` claim is present in the token obtained from Microsoft identity platform. ")]
    public static partial void MissingTenantIdClaim(this ILogger logger);

    [LoggerMessage(
        EventId = 40004,
        Level = LogLevel.Error,
        Message = "IDX40004: Token issuer: '{tokenIssuer}', does not contain the `tid` or `tenantId` claim present in the token: '{tenantId}'.")]
    public static partial void TokenIssuerDoesNotContainTenantId(this ILogger logger, string tokenIssuer, string tenantId);

    [LoggerMessage(
        EventId = 40005,
        Level = LogLevel.Error,
        Message = "IDX40005: Token issuer: '{tokenIssuer}', does not match the signing key issuer: '{signingKeyIssuer}'.")]
    public static partial void TokenIssuerDoesNotMatchSigningKeyIssuer(this ILogger logger, string tokenIssuer, string signingKeyIssuer);

    [LoggerMessage(
        EventId = 40007,
        Level = LogLevel.Error,
        Message = "IDX40007: RequireSignedTokens property on ValidationParameters is set to true, but the issuer signing key is null.")]
    public static partial void NullIssuerSigningKey(this ILogger logger);

    [LoggerMessage(
        EventId = 40008,
        Level = LogLevel.Error,
        Message = "IDX40008: When setting LastKnownGoodLifetime, the value must be greater than or equal to zero. value: '{value}'.")]
    public static partial void InvalidLastKnownGoodLifetime(this ILogger logger, TimeSpan value);

    [LoggerMessage(
        EventId = 40009,
        Level = LogLevel.Error,
        Message = "IDX40009: Either the 'tid' claim was not found or it didn't have a value.")]
    public static partial void MissingOrEmptyTenantIdClaim(this ILogger logger);

    [LoggerMessage(
        EventId = 40010,
        Level = LogLevel.Error,
        Message = "IDX40010: The SecurityToken must be a 'JsonWebToken' or 'JwtSecurityToken'")]
    public static partial void InvalidSecurityTokenType(this ILogger logger);

    [LoggerMessage(
        EventId = 40011,
        Level = LogLevel.Error,
        Message = "IDX40011: The SecurityToken has multiple instances of the '{claimType}' claim.")]
    public static partial void MultipleClaimInstances(this ILogger logger, string claimType);

    [LoggerMessage(
        EventId = 40012,
        Level = LogLevel.Error,
        Message = "IDX40012: The cloud instance of the signing key: '{signingKeyCloudInstance}', does not match cloud instance from configuration: '{configurationCloudInstance}'.")]
    public static partial void SigningKeyCloudInstanceMismatch(this ILogger logger, string signingKeyCloudInstance, string configurationCloudInstance);
#else
    private static readonly Action<ILogger, string, Exception> s_noValidIssuerMatch = LoggerMessage.Define<string>(
        LogLevel.Error,
        new EventId(40001, nameof(NoValidIssuerMatch)),
        "IDX40001: Issuer: '{issuer}', does not match any of the valid issuers provided for this application. ");

    public static void NoValidIssuerMatch(this ILogger logger, string issuer) =>
        s_noValidIssuerMatch(logger, issuer, null);

    private static readonly Action<ILogger, Exception> s_unsupportedB2CIssuer = LoggerMessage.Define(
        LogLevel.Error,
        new EventId(40002, nameof(UnsupportedB2CIssuer)),
        "IDX40002: Microsoft.IdentityModel does not support a B2C issuer with 'tfp' in the URI. See https://aka.ms/ms-id-web/b2c-issuer for details. ");

    public static void UnsupportedB2CIssuer(this ILogger logger) =>
        s_unsupportedB2CIssuer(logger, null);

    private static readonly Action<ILogger, Exception> s_missingTenantIdClaim = LoggerMessage.Define(
        LogLevel.Error,
        new EventId(40003, nameof(MissingTenantIdClaim)),
        "IDX40003: Neither `tid` nor `tenantId` claim is present in the token obtained from Microsoft identity platform. ");

    public static void MissingTenantIdClaim(this ILogger logger) =>
        s_missingTenantIdClaim(logger, null);

    private static readonly Action<ILogger, string, string, Exception> s_tokenIssuerDoesNotContainTenantId = LoggerMessage.Define<string, string>(
        LogLevel.Error,
        new EventId(40004, nameof(TokenIssuerDoesNotContainTenantId)),
        "IDX40004: Token issuer: '{tokenIssuer}', does not contain the `tid` or `tenantId` claim present in the token: '{tenantId}'.");

    public static void TokenIssuerDoesNotContainTenantId(this ILogger logger, string tokenIssuer, string tenantId) =>
        s_tokenIssuerDoesNotContainTenantId(logger, tokenIssuer, tenantId, null);

    private static readonly Action<ILogger, string, string, Exception> s_tokenIssuerDoesNotMatchSigningKeyIssuer = LoggerMessage.Define<string, string>(
        LogLevel.Error,
        new EventId(40005, nameof(TokenIssuerDoesNotMatchSigningKeyIssuer)),
        "IDX40005: Token issuer: '{tokenIssuer}', does not match the signing key issuer: '{signingKeyIssuer}'.");

    public static void TokenIssuerDoesNotMatchSigningKeyIssuer(this ILogger logger, string tokenIssuer, string signingKeyIssuer) =>
        s_tokenIssuerDoesNotMatchSigningKeyIssuer(logger, tokenIssuer, signingKeyIssuer, null);

    private static readonly Action<ILogger, Exception> s_nullIssuerSigningKey = LoggerMessage.Define(
        LogLevel.Error,
        new EventId(40007, nameof(NullIssuerSigningKey)),
        "IDX40007: RequireSignedTokens property on ValidationParameters is set to true, but the issuer signing key is null.");

    public static void NullIssuerSigningKey(this ILogger logger) =>
        s_nullIssuerSigningKey(logger, null);

    private static readonly Action<ILogger, TimeSpan, Exception> s_invalidLastKnownGoodLifetime = LoggerMessage.Define<TimeSpan>(
        LogLevel.Error,
        new EventId(40008, nameof(InvalidLastKnownGoodLifetime)),
        "IDX40008: When setting LastKnownGoodLifetime, the value must be greater than or equal to zero. value: '{value}'.");

    public static void InvalidLastKnownGoodLifetime(this ILogger logger, TimeSpan value) =>
        s_invalidLastKnownGoodLifetime(logger, value, null);

    private static readonly Action<ILogger, Exception> s_missingOrEmptyTenantIdClaim = LoggerMessage.Define(
        LogLevel.Error,
        new EventId(40009, nameof(MissingOrEmptyTenantIdClaim)),
        "IDX40009: Either the 'tid' claim was not found or it didn't have a value.");

    public static void MissingOrEmptyTenantIdClaim(this ILogger logger) =>
        s_missingOrEmptyTenantIdClaim(logger, null);

    private static readonly Action<ILogger, Exception> s_invalidSecurityTokenType = LoggerMessage.Define(
        LogLevel.Error,
        new EventId(40010, nameof(InvalidSecurityTokenType)),
        "IDX40010: The SecurityToken must be a 'JsonWebToken' or 'JwtSecurityToken'");

    public static void InvalidSecurityTokenType(this ILogger logger) =>
        s_invalidSecurityTokenType(logger, null);

    private static readonly Action<ILogger, string, Exception> s_multipleClaimInstances = LoggerMessage.Define<string>(
        LogLevel.Error,
        new EventId(40011, nameof(MultipleClaimInstances)),
        "IDX40011: The SecurityToken has multiple instances of the '{claimType}' claim.");

    public static void MultipleClaimInstances(this ILogger logger, string claimType) =>
        s_multipleClaimInstances(logger, claimType, null);

    private static readonly Action<ILogger, string, string, Exception> s_signingKeyCloudInstanceMismatch = LoggerMessage.Define<string, string>(
        LogLevel.Error,
        new EventId(40012, nameof(SigningKeyCloudInstanceMismatch)),
        "IDX40012: The cloud instance of the signing key: '{signingKeyCloudInstance}', does not match cloud instance from configuration: '{configurationCloudInstance}'.");

    public static void SigningKeyCloudInstanceMismatch(this ILogger logger, string signingKeyCloudInstance, string configurationCloudInstance) =>
        s_signingKeyCloudInstanceMismatch(logger, signingKeyCloudInstance, configurationCloudInstance, null);
#endif
}
