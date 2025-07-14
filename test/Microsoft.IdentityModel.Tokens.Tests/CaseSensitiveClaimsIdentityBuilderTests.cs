// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class CaseSensitiveClaimsIdentityBuilderTests
    {
        [Fact]
        public void Create_ReturnsBuilder()
        {
            // Act
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();

            // Assert
            Assert.NotNull(builder);
        }

        [Fact]
        public void WithAuthenticationType_ValidType_ReturnsBuilder()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();
            var authenticationType = "Bearer";

            // Act
            var result = builder.WithAuthenticationType(authenticationType);

            // Assert
            Assert.Same(builder, result);
        }

        [Fact]
        public void WithAuthenticationType_NullType_ThrowsArgumentNullException()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => builder.WithAuthenticationType(null));
        }

        [Fact]
        public void WithNameType_ValidType_ReturnsBuilder()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();
            var nameType = ClaimTypes.Name;

            // Act
            var result = builder.WithNameType(nameType);

            // Assert
            Assert.Same(builder, result);
        }

        [Fact]
        public void WithNameType_NullType_ThrowsArgumentNullException()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => builder.WithNameType(null));
        }

        [Fact]
        public void WithRoleType_ValidType_ReturnsBuilder()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();
            var roleType = ClaimTypes.Role;

            // Act
            var result = builder.WithRoleType(roleType);

            // Assert
            Assert.Same(builder, result);
        }

        [Fact]
        public void WithRoleType_NullType_ThrowsArgumentNullException()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => builder.WithRoleType(null));
        }

        [Fact]
        public void WithClaim_ValidClaim_ReturnsBuilder()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();
            var claim = new Claim("test", "value");

            // Act
            var result = builder.WithClaim(claim);

            // Assert
            Assert.Same(builder, result);
        }

        [Fact]
        public void WithClaim_NullClaim_ThrowsArgumentNullException()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => builder.WithClaim((Claim)null));
        }

        [Fact]
        public void WithClaim_TypeAndValue_ReturnsBuilder()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();
            var type = "test";
            var value = "value";

            // Act
            var result = builder.WithClaim(type, value);

            // Assert
            Assert.Same(builder, result);
        }

        [Fact]
        public void WithClaim_NullType_ThrowsArgumentNullException()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => builder.WithClaim(null, "value"));
        }

        [Fact]
        public void WithClaim_NullValue_ThrowsArgumentNullException()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => builder.WithClaim("type", null));
        }

        [Fact]
        public void WithClaims_ValidClaims_ReturnsBuilder()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();
            var claims = new List<Claim>
            {
                new Claim("test1", "value1"),
                new Claim("test2", "value2")
            };

            // Act
            var result = builder.WithClaims(claims);

            // Assert
            Assert.Same(builder, result);
        }

        [Fact]
        public void WithClaims_NullClaims_ThrowsArgumentNullException()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => builder.WithClaims(null));
        }

        [Fact]
        public void WithClaims_ClaimsWithNulls_FiltersNulls()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();
            var claims = new List<Claim>
            {
                new Claim("test1", "value1"),
                null,
                new Claim("test2", "value2")
            };

            // Act
            var identity = builder.WithClaims(claims).Build();

            // Assert
            Assert.Equal(2, identity.Claims.Count());
            Assert.Contains(identity.Claims, c => c.Type == "test1" && c.Value == "value1");
            Assert.Contains(identity.Claims, c => c.Type == "test2" && c.Value == "value2");
        }

        [Fact]
        public void FromClaimsIdentity_ValidIdentity_ReturnsBuilder()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();
            var identity = new ClaimsIdentity();

            // Act
            var result = builder.FromClaimsIdentity(identity);

            // Assert
            Assert.Same(builder, result);
        }

        [Fact]
        public void FromClaimsIdentity_NullIdentity_ThrowsArgumentNullException()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => builder.FromClaimsIdentity(null));
        }

        [Fact]
        public void WithSecurityToken_ValidToken_ReturnsBuilder()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();
            var token = new TestSecurityToken();

            // Act
            var result = builder.WithSecurityToken(token);

            // Assert
            Assert.Same(builder, result);
        }

        [Fact]
        public void WithSecurityToken_NullToken_ReturnsBuilder()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();

            // Act
            var result = builder.WithSecurityToken(null);

            // Assert
            Assert.Same(builder, result);
        }

        [Fact]
        public void Build_DefaultConstructor_CreatesEmptyIdentity()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();

            // Act
            var identity = builder.Build();

            // Assert
            Assert.NotNull(identity);
            Assert.IsType<CaseSensitiveClaimsIdentity>(identity);
            Assert.Empty(identity.Claims);
            Assert.Null(identity.AuthenticationType);
        }

        [Fact]
        public void Build_AuthenticationTypeOnly_UsesAuthConstructor()
        {
            // Arrange
            var authenticationType = "Bearer";
            var builder = CaseSensitiveClaimsIdentityBuilder.Create()
                .WithAuthenticationType(authenticationType);

            // Act
            var identity = builder.Build();

            // Assert
            Assert.NotNull(identity);
            Assert.IsType<CaseSensitiveClaimsIdentity>(identity);
            Assert.Equal(authenticationType, identity.AuthenticationType);
            Assert.Empty(identity.Claims);
        }

        [Fact]
        public void Build_ClaimsOnly_UsesClaimsConstructor()
        {
            // Arrange
            var claims = new List<Claim>
            {
                new Claim("test1", "value1"),
                new Claim("test2", "value2")
            };
            var builder = CaseSensitiveClaimsIdentityBuilder.Create()
                .WithClaims(claims);

            // Act
            var identity = builder.Build();

            // Assert
            Assert.NotNull(identity);
            Assert.IsType<CaseSensitiveClaimsIdentity>(identity);
            Assert.Equal(2, identity.Claims.Count());
            Assert.Null(identity.AuthenticationType);
        }

        [Fact]
        public void Build_ClaimsAndAuthenticationType_UsesClaimsAuthConstructor()
        {
            // Arrange
            var authenticationType = "Bearer";
            var claims = new List<Claim>
            {
                new Claim("test1", "value1"),
                new Claim("test2", "value2")
            };
            var builder = CaseSensitiveClaimsIdentityBuilder.Create()
                .WithAuthenticationType(authenticationType)
                .WithClaims(claims);

            // Act
            var identity = builder.Build();

            // Assert
            Assert.NotNull(identity);
            Assert.IsType<CaseSensitiveClaimsIdentity>(identity);
            Assert.Equal(authenticationType, identity.AuthenticationType);
            Assert.Equal(2, identity.Claims.Count());
        }

        [Fact]
        public void Build_AuthenticationTypeNameTypeRoleType_UsesTypesConstructor()
        {
            // Arrange
            var authenticationType = "Bearer";
            var nameType = ClaimTypes.Name;
            var roleType = ClaimTypes.Role;
            var builder = CaseSensitiveClaimsIdentityBuilder.Create()
                .WithAuthenticationType(authenticationType)
                .WithNameType(nameType)
                .WithRoleType(roleType);

            // Act
            var identity = builder.Build();

            // Assert
            Assert.NotNull(identity);
            Assert.IsType<CaseSensitiveClaimsIdentity>(identity);
            Assert.Equal(authenticationType, identity.AuthenticationType);
            Assert.Equal(nameType, identity.NameClaimType);
            Assert.Equal(roleType, identity.RoleClaimType);
        }

        [Fact]
        public void Build_FullParameters_UsesFullConstructor()
        {
            // Arrange
            var authenticationType = "Bearer";
            var nameType = ClaimTypes.Name;
            var roleType = ClaimTypes.Role;
            var claims = new List<Claim>
            {
                new Claim("test1", "value1"),
                new Claim("test2", "value2")
            };
            var builder = CaseSensitiveClaimsIdentityBuilder.Create()
                .WithAuthenticationType(authenticationType)
                .WithNameType(nameType)
                .WithRoleType(roleType)
                .WithClaims(claims);

            // Act
            var identity = builder.Build();

            // Assert
            Assert.NotNull(identity);
            Assert.IsType<CaseSensitiveClaimsIdentity>(identity);
            Assert.Equal(authenticationType, identity.AuthenticationType);
            Assert.Equal(nameType, identity.NameClaimType);
            Assert.Equal(roleType, identity.RoleClaimType);
            Assert.Equal(2, identity.Claims.Count());
        }

        [Fact]
        public void Build_FromClaimsIdentity_UsesCopyConstructor()
        {
            // Arrange
            var baseIdentity = new ClaimsIdentity(new[]
            {
                new Claim("existing", "claim")
            }, "Original");
            var builder = CaseSensitiveClaimsIdentityBuilder.Create()
                .FromClaimsIdentity(baseIdentity);

            // Act
            var identity = builder.Build();

            // Assert
            Assert.NotNull(identity);
            Assert.IsType<CaseSensitiveClaimsIdentity>(identity);
            Assert.Equal("Original", identity.AuthenticationType);
            Assert.Single(identity.Claims);
            Assert.Equal("existing", identity.Claims.First().Type);
        }

        [Fact]
        public void Build_FromClaimsIdentityWithAdditionalClaims_CombinesClaims()
        {
            // Arrange
            var baseIdentity = new ClaimsIdentity(new[]
            {
                new Claim("existing", "claim")
            }, "Original");
            var additionalClaim = new Claim("additional", "claim");
            var builder = CaseSensitiveClaimsIdentityBuilder.Create()
                .FromClaimsIdentity(baseIdentity)
                .WithClaim(additionalClaim);

            // Act
            var identity = builder.Build();

            // Assert
            Assert.NotNull(identity);
            Assert.IsType<CaseSensitiveClaimsIdentity>(identity);
            Assert.Equal(2, identity.Claims.Count());
            Assert.Contains(identity.Claims, c => c.Type == "existing");
            Assert.Contains(identity.Claims, c => c.Type == "additional");
        }

        [Fact]
        public void Build_WithSecurityToken_AssignsToken()
        {
            // Arrange
            var token = new TestSecurityToken();
            var builder = CaseSensitiveClaimsIdentityBuilder.Create()
                .WithSecurityToken(token);

            // Act
            var identity = builder.Build();

            // Assert
            Assert.NotNull(identity);
            Assert.Same(token, identity.SecurityToken);
        }

        [Fact]
        public void FluentChaining_AllMethods_ReturnsBuilder()
        {
            // Arrange & Act
            var identity = CaseSensitiveClaimsIdentityBuilder.Create()
                .WithAuthenticationType("Bearer")
                .WithNameType(ClaimTypes.Name)
                .WithRoleType(ClaimTypes.Role)
                .WithClaim("test", "value")
                .WithClaims(new[] { new Claim("test2", "value2") })
                .WithSecurityToken(new TestSecurityToken())
                .Build();

            // Assert
            Assert.NotNull(identity);
            Assert.IsType<CaseSensitiveClaimsIdentity>(identity);
            Assert.Equal("Bearer", identity.AuthenticationType);
            Assert.Equal(ClaimTypes.Name, identity.NameClaimType);
            Assert.Equal(ClaimTypes.Role, identity.RoleClaimType);
            Assert.Equal(2, identity.Claims.Count());
            Assert.NotNull(identity.SecurityToken);
        }

        [Fact]
        public void Build_MultipleTimes_CreatesSeparateInstances()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create()
                .WithAuthenticationType("Bearer")
                .WithClaim("test", "value");

            // Act
            var identity1 = builder.Build();
            var identity2 = builder.Build();

            // Assert
            Assert.NotNull(identity1);
            Assert.NotNull(identity2);
            Assert.NotSame(identity1, identity2);
            Assert.Equal(identity1.AuthenticationType, identity2.AuthenticationType);
            Assert.Equal(identity1.Claims.Count(), identity2.Claims.Count());
        }

        [Theory]
        [InlineData("", "name", "role", false)] // Empty auth type
        [InlineData("auth", "", "role", false)] // Empty name type
        [InlineData("auth", "name", "", false)] // Empty role type
        [InlineData("auth", "name", "role", true)] // All valid
        public void Build_TypesConstructorSelection_ValidatesAllTypesPresent(
            string authType, string nameType, string roleType, bool shouldUseTypesConstructor)
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();
            
            if (!string.IsNullOrEmpty(authType))
                builder = builder.WithAuthenticationType(authType);
            if (!string.IsNullOrEmpty(nameType))
                builder = builder.WithNameType(nameType);
            if (!string.IsNullOrEmpty(roleType))
                builder = builder.WithRoleType(roleType);

            // Act
            var identity = builder.Build();

            // Assert
            Assert.NotNull(identity);
            if (shouldUseTypesConstructor)
            {
                Assert.Equal(authType, identity.AuthenticationType);
                Assert.Equal(nameType, identity.NameClaimType);
                Assert.Equal(roleType, identity.RoleClaimType);
            }
            else
            {
                // Should fall back to simpler constructor or default
                if (!string.IsNullOrEmpty(authType))
                {
                    Assert.Equal(authType, identity.AuthenticationType);
                }
            }
        }

        [Fact]
        public void WithClaims_EmptyCollection_DoesNotAddClaims()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create();
            var emptyClaims = new List<Claim>();

            // Act
            var identity = builder.WithClaims(emptyClaims).Build();

            // Assert
            Assert.NotNull(identity);
            Assert.Empty(identity.Claims);
        }

        [Fact]
        public void Build_CaseSensitivityPreserved_VerifyClaimRetrieval()
        {
            // Arrange
            var lowerCaseClaim = new Claim("tid", "tenant");
            var upperCaseClaim = new Claim("TID", "TENANT");
            var builder = CaseSensitiveClaimsIdentityBuilder.Create()
                .WithClaim(lowerCaseClaim)
                .WithClaim(upperCaseClaim);

            // Act
            var identity = builder.Build();

            // Assert
            Assert.NotNull(identity);
            Assert.IsType<CaseSensitiveClaimsIdentity>(identity);
            
            // Verify case-sensitive behavior
            var lowerResult = identity.FindFirst("tid");
            var upperResult = identity.FindFirst("TID");
            
            Assert.NotNull(lowerResult);
            Assert.NotNull(upperResult);
            Assert.Equal("tid", lowerResult.Type);
            Assert.Equal("TID", upperResult.Type);
            Assert.NotSame(lowerResult, upperResult);
        }

        [Fact]
        public void Build_WithMultipleCalls_DoesNotAffectPreviousInstances()
        {
            // Arrange
            var builder = CaseSensitiveClaimsIdentityBuilder.Create()
                .WithAuthenticationType("Bearer");

            // Act
            var identity1 = builder.Build();
            builder.WithClaim("additional", "claim");
            var identity2 = builder.Build();

            // Assert
            Assert.Equal(0, identity1.Claims.Count()); // Original should be unchanged
            Assert.Equal(1, identity2.Claims.Count()); // New instance has additional claim
        }

        // Test helper class
        private class TestSecurityToken : SecurityToken
        {
            public override string Id => "test-token";
            public override string Issuer => "test-issuer";
            public override SecurityKey SecurityKey => null;
            public override SecurityKey SigningKey { get; set; }
            public override DateTime ValidFrom => DateTime.UtcNow;
            public override DateTime ValidTo => DateTime.UtcNow.AddHours(1);
        }
    }
}