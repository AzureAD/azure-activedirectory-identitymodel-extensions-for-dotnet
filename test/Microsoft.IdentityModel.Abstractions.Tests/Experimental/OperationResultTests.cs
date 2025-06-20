// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Abstractions.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.Abstractions.Tests.Experimental
{
    public class OperationResultTests
    {
        [Fact]
        public void ValidResult()
        {
            var expected = "success";
            var result = new OperationResult<string, OperationError>(expected);

            Assert.True(result.IsValid);
            Assert.Equal(expected, result.Result);
            Assert.Null(result.Error);
        }

        [Fact]
        public void ErrorResult()
        {
            var expectedError = new CustomError();
            var result = new OperationResult<string, OperationError>(expectedError);

            Assert.False(result.IsValid);
            Assert.Equal(expectedError, result.Error);
            Assert.Null(result.Result);
        }

        [Fact]
        public void SuccessAndError()
        {
            var success = new OperationResult<string, OperationError>("42");
            Assert.True(success.IsValid);
            Assert.Equal("42", success.Result);
            Assert.Null(success.Error);

            var error = new OperationResult<string, OperationError>(new CustomError());
            Assert.False(error.IsValid);
            Assert.NotNull(error.Error);
            Assert.Null(error.Result);
        }

        public class CustomError : OperationError
        {
            public string ErrorMessage { get; set; }
        }
    }
}
