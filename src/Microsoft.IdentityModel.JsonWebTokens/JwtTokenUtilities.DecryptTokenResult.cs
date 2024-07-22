using System;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Abstractions;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;
using System.Diagnostics;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    public partial class JwtTokenUtilities
    {
        /// <summary>
        /// Decrypts a JWT token.
        /// </summary>
        /// <param name="jsonWebToken">The JWT token to decrypt.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="decryptionParameters">The decryption parameters container.</param>
        /// <param name="callContext">The call context used for logging.</param>
        /// <returns>The decrypted, and if the 'zip' claim is set, decompressed string representation of the token.</returns>
        internal static TokenDecryptingResult DecryptJwtToken(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            JwtTokenDecryptionParameters decryptionParameters,
            CallContext callContext)
        {
            if (validationParameters == null)
                return new TokenDecryptingResult(
                    jsonWebToken,
                    ValidationFailureType.NullArgument,
                    new ExceptionDetail(
                        new MessageDetail(
                            TokenLogMessages.IDX10000,
                            nameof(validationParameters)),
                        typeof(ArgumentNullException),
                        new System.Diagnostics.StackFrame()));

            if (decryptionParameters == null)
                return new TokenDecryptingResult(
                    jsonWebToken,
                    ValidationFailureType.NullArgument,
                    new ExceptionDetail(
                        new MessageDetail(
                            TokenLogMessages.IDX10000,
                            nameof(decryptionParameters)),
                        typeof(ArgumentNullException),
                        new System.Diagnostics.StackFrame()));

            bool decryptionSucceeded = false;
            bool algorithmNotSupportedByCryptoProvider = false;
            byte[] decryptedTokenBytes = null;

            // keep track of exceptions thrown, keys that were tried
            StringBuilder exceptionStrings = null;
            StringBuilder keysAttempted = null;
            string zipAlgorithm = null;
            foreach (SecurityKey key in decryptionParameters.Keys)
            {
                var cryptoProviderFactory = validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory;
                if (cryptoProviderFactory == null)
                {
                    if (LogHelper.IsEnabled(EventLogLevel.Warning))
                        LogHelper.LogWarning(TokenLogMessages.IDX10607, key);

                    continue;
                }

                try
                {
                    if (!cryptoProviderFactory.IsSupportedAlgorithm(jsonWebToken.Enc, key))
                    {
                        if (LogHelper.IsEnabled(EventLogLevel.Warning))
                            LogHelper.LogWarning(TokenLogMessages.IDX10611, LogHelper.MarkAsNonPII(decryptionParameters.Enc), key);

                        algorithmNotSupportedByCryptoProvider = true;
                        continue;
                    }

                    AlgorithmValidationResult result = validationParameters.AlgorithmValidator(zipAlgorithm, key, jsonWebToken, validationParameters, callContext);
                    if (!result.IsValid)
                    {
                        (exceptionStrings ??= new StringBuilder()).AppendLine(result.ExceptionDetail.MessageDetail.Message);
                        continue;
                    }

                    decryptedTokenBytes = DecryptToken(
                        cryptoProviderFactory,
                        key,
                        jsonWebToken.Enc,
                        jsonWebToken.CipherTextBytes,
                        jsonWebToken.HeaderAsciiBytes,
                        jsonWebToken.InitializationVectorBytes,
                        jsonWebToken.AuthenticationTagBytes);

                    zipAlgorithm = jsonWebToken.Zip;
                    decryptionSucceeded = true;
                    break;
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    (exceptionStrings ??= new StringBuilder()).AppendLine(ex.ToString());
                }

                if (key != null)
                    (keysAttempted ??= new StringBuilder()).AppendLine(key.ToString());
            }

            ExceptionDetail exceptionDetail = ValidateDecryption(
                decryptionParameters,
                decryptionSucceeded,
                algorithmNotSupportedByCryptoProvider,
                exceptionStrings,
                keysAttempted,
                callContext);

            if (exceptionDetail != null)
                return new TokenDecryptingResult(
                    jsonWebToken,
                    ValidationFailureType.TokenDecryptingFailed,
                    exceptionDetail);

            try
            {
                string decodedString;
                if (string.IsNullOrEmpty(zipAlgorithm))
                    decodedString = Encoding.UTF8.GetString(decryptedTokenBytes);
                else
                    decodedString = decryptionParameters.DecompressionFunction(decryptedTokenBytes, zipAlgorithm, decryptionParameters.MaximumDeflateSize);

                return new TokenDecryptingResult(decodedString, jsonWebToken);
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new TokenDecryptingResult(
                    jsonWebToken,
                    ValidationFailureType.TokenDecryptingFailed,
                    new ExceptionDetail(
                        new MessageDetail(
                            TokenLogMessages.IDX10679,
                            zipAlgorithm),
                        typeof(SecurityTokenDecompressionFailedException),
                        new StackFrame(),
                        ex));
            }
        }
    }
}
