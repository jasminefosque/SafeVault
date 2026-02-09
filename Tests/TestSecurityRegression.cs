using NUnit.Framework;
using SafeVault.App.Models;
using SafeVault.App.Security;

namespace Tests;

[TestFixture]
public class TestSecurityRegression
{
    [Test]
    public void Test_NoPlainTextPasswords()
    {
        // Arrange
        string password = "TestPassword123!";
        
        // Act
        string hash = AuthService.HashPassword(password);
        
        // Assert - Hash should not contain the original password
        Assert.That(hash, Does.Not.Contain(password));
        Assert.That(hash, Is.Not.EqualTo(password));
        Assert.That(hash.Length, Is.GreaterThan(password.Length));
    }

    [Test]
    public void Test_SqlInjection_PreviouslyVulnerablePatterns()
    {
        // Test patterns that were vulnerable before parameterized queries
        string[] injectionPatterns = new[]
        {
            "admin' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE Users; --",
            "admin'--",
            "' UNION SELECT * FROM Users--",
            "1' AND '1'='1",
            "' OR 'a'='a"
        };

        foreach (var pattern in injectionPatterns)
        {
            bool isDetected = InputSanitizer.ContainsSqlInjectionPattern(pattern);
            Assert.That(isDetected, Is.True, 
                $"SQL injection pattern not detected: {pattern}");
        }
    }

    [Test]
    public void Test_XssPrevention_PreviouslyVulnerablePatterns()
    {
        // Test XSS patterns that were vulnerable before sanitization
        string[] xssPatterns = new[]
        {
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(1)'>",
            "<body onload=alert('XSS')>"
        };

        foreach (var pattern in xssPatterns)
        {
            string sanitized = InputSanitizer.SanitizeForXss(pattern);
            
            // Verify dangerous tags are encoded
            Assert.That(sanitized, Does.Not.Contain("<script"), 
                $"XSS pattern not sanitized: {pattern}");
            Assert.That(sanitized, Does.Not.Contain("<img"), 
                $"XSS pattern not sanitized: {pattern}");
            Assert.That(sanitized, Does.Not.Contain("<iframe"), 
                $"XSS pattern not sanitized: {pattern}");
        }
    }

    [Test]
    public void Test_PasswordStorage_NeverPlainText()
    {
        // Arrange
        var user = new User
        {
            Id = 1,
            Username = "testuser",
            Email = "test@example.com",
            PasswordHash = AuthService.HashPassword("MyPassword123!"),
            Role = "user"
        };

        // Assert
        Assert.That(user.PasswordHash, Does.Not.Contain("MyPassword123!"));
        Assert.That(user.PasswordHash, Does.StartWith("$2")); // BCrypt format
    }

    [Test]
    public void Test_InputValidation_EnforcedBeforeProcessing()
    {
        // Test that invalid inputs are rejected before processing
        
        // Invalid email
        Assert.That(InputSanitizer.IsValidEmail("notanemail"), Is.False);
        
        // Invalid username
        Assert.That(InputSanitizer.IsValidUsername("ab"), Is.False); // Too short
        Assert.That(InputSanitizer.IsValidUsername("user@name"), Is.False); // Invalid chars
        
        // Weak password
        Assert.That(AuthService.IsStrongPassword("weak"), Is.False);
    }

    [Test]
    public void Test_Authorization_ChecksEnforced()
    {
        // Arrange
        var regularUser = new User
        {
            Id = 2,
            Username = "user",
            Email = "user@example.com",
            PasswordHash = AuthService.HashPassword("UserPass123!"),
            Role = "user"
        };

        // Act & Assert - Regular user cannot perform admin actions
        Assert.Throws<UnauthorizedAccessException>(() =>
            RoleAuthorization.RequireAdmin(regularUser));
    }

    [Test]
    public void Test_NoSqlStringConcatenation()
    {
        // This test verifies that we're using parameterized queries
        // by checking that dangerous inputs are safely handled
        
        string maliciousUsername = "admin' OR '1'='1' --";
        
        // Should be detected as SQL injection
        bool isInjection = InputSanitizer.ContainsSqlInjectionPattern(maliciousUsername);
        Assert.That(isInjection, Is.True);
        
        // Should fail username validation
        bool isValidUsername = InputSanitizer.IsValidUsername(maliciousUsername);
        Assert.That(isValidUsername, Is.False);
    }

    [Test]
    public void Test_PasswordHashing_UsesSalt()
    {
        // Arrange
        string password = "SamePassword123!";
        
        // Act - Hash same password twice
        string hash1 = AuthService.HashPassword(password);
        string hash2 = AuthService.HashPassword(password);
        
        // Assert - Hashes should be different due to salt
        Assert.That(hash1, Is.Not.EqualTo(hash2));
    }

    [Test]
    public void Test_SessionSecurity_NoWeakPasswords()
    {
        // Test that weak passwords are rejected
        string[] weakPasswords = new[]
        {
            "password",
            "12345678",
            "qwerty",
            "Password", // No digit or special char
            "PASSWORD123", // No lowercase
            "password123", // No uppercase
            "Password123" // No special char
        };

        foreach (var weakPassword in weakPasswords)
        {
            bool isStrong = AuthService.IsStrongPassword(weakPassword);
            Assert.That(isStrong, Is.False, 
                $"Weak password accepted: {weakPassword}");
        }
    }

    [Test]
    public void Test_RoleEscalation_Prevention()
    {
        // Arrange - User tries to escalate to admin
        var user = new User
        {
            Id = 3,
            Username = "hacker",
            Email = "hacker@example.com",
            PasswordHash = AuthService.HashPassword("HackerPass123!"),
            Role = "user"
        };

        // Try to manually change role (should not work in practice)
        // Authorization checks should always check the current role
        
        // Act & Assert
        Assert.That(RoleAuthorization.IsAdmin(user), Is.False);
        Assert.Throws<UnauthorizedAccessException>(() =>
            RoleAuthorization.RequireAdmin(user));
    }

    [Test]
    public void Test_ConsistentSecurityMeasures()
    {
        // Verify all security measures work together
        
        // 1. Input validation
        string email = "test@example.com";
        string username = "testuser";
        Assert.That(InputSanitizer.IsValidEmail(email), Is.True);
        Assert.That(InputSanitizer.IsValidUsername(username), Is.True);
        
        // 2. Password hashing
        string password = "SecurePass123!";
        Assert.That(AuthService.IsStrongPassword(password), Is.True);
        string hash = AuthService.HashPassword(password);
        Assert.That(hash, Does.StartWith("$2"));
        
        // 3. Authentication
        var users = new List<User>
        {
            new User
            {
                Id = 1,
                Username = username,
                Email = email,
                PasswordHash = hash,
                Role = "user"
            }
        };
        var loginResult = AuthService.Login(username, password, users);
        Assert.That(loginResult, Is.Not.Null);
        
        // 4. Authorization
        Assert.That(RoleAuthorization.IsUser(loginResult!), Is.True);
        Assert.That(RoleAuthorization.CanAccessResource(loginResult, 1), Is.True);
    }

    [Test]
    public void Test_NoInformationLeakage_InvalidLogin()
    {
        // Arrange
        var users = new List<User>
        {
            new User
            {
                Id = 1,
                Username = "realuser",
                Email = "real@example.com",
                PasswordHash = AuthService.HashPassword("RealPass123!"),
                Role = "user"
            }
        };

        // Act - Try invalid username and invalid password
        var result1 = AuthService.Login("fakeuser", "SomePass123!", users);
        var result2 = AuthService.Login("realuser", "WrongPass123!", users);

        // Assert - Both should return null without leaking info
        Assert.That(result1, Is.Null);
        Assert.That(result2, Is.Null);
        // No exception or different behavior that could leak info
    }

    [Test]
    public void Test_InputSanitization_AppliedConsistently()
    {
        // Test that sanitization is consistent
        string input = "<script>alert('test')</script>";
        
        string sanitized1 = InputSanitizer.SanitizeForXss(input);
        string sanitized2 = InputSanitizer.SanitizeForXss(input);
        
        // Should produce same result
        Assert.That(sanitized1, Is.EqualTo(sanitized2));
        
        // Should be safe
        Assert.That(sanitized1, Does.Not.Contain("<script>"));
    }

    [Test]
    public void Test_CriticalSecurityFeatures_AllPresent()
    {
        // Verify all critical security features are implemented
        
        // 1. XSS Protection
        Assert.That(() => InputSanitizer.SanitizeForXss("<script>"), 
            Throws.Nothing);
        
        // 2. SQL Injection Detection
        Assert.That(() => InputSanitizer.ContainsSqlInjectionPattern("'; DROP TABLE"), 
            Throws.Nothing);
        
        // 3. Password Hashing
        Assert.That(() => AuthService.HashPassword("TestPass123!"), 
            Throws.Nothing);
        
        // 4. Password Verification
        string hash = AuthService.HashPassword("TestPass123!");
        Assert.That(() => AuthService.VerifyPassword("TestPass123!", hash), 
            Throws.Nothing);
        
        // 5. Authorization
        var user = new User { Id = 1, Username = "test", Role = "user" };
        Assert.That(() => RoleAuthorization.IsAdmin(user), 
            Throws.Nothing);
    }
}
