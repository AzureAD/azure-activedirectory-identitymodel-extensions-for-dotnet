// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Runtime.CompilerServices;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class ValidationErrorTests
    {
        [Fact]
        public void ExceptionCreatedFromValidationError_ContainsTheRightStackTrace()
        {
            var validationError = new ValidationErrorReturningClass().firstMethod();
            Assert.NotNull(validationError);
            Assert.NotNull(validationError.StackFrames);
            Assert.Equal(3, validationError.StackFrames.Count);
            Assert.NotNull(validationError.GetException());
            Assert.NotNull(validationError.GetException().StackTrace);
            Assert.Equal("thirdMethod", validationError.StackFrames[0].GetMethod().Name);
            Assert.Equal("secondMethod", validationError.StackFrames[1].GetMethod().Name);
            Assert.Equal("firstMethod", validationError.StackFrames[2].GetMethod().Name);
        }
        class ValidationErrorReturningClass
        {
            [MethodImpl(MethodImplOptions.NoInlining)]
            public ValidationError firstMethod()
            {
                return secondMethod().AddCurrentStackFrame();
            }

            [MethodImpl(MethodImplOptions.NoInlining)]
            public ValidationError secondMethod()
            {
                return thirdMethod().AddCurrentStackFrame();
            }

            public ValidationError thirdMethod()
            {
                return new ValidationError(
                    new MessageDetail("This is a test error"),
                    ValidationFailureType.NullArgument,
                    typeof(SecurityTokenArgumentNullException),
                    ValidationError.GetCurrentStackFrame());
            }
        }
    }
}
