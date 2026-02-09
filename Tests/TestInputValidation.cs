using NUnit.Framework;
using SafeVault.App.Security;

namespace Tests;

[TestFixture]
public class TestInputValidation
{
    [Test]
    public void Test_SanitizeForXss_RemovesScriptTags()
    {
        // Arrange
        string maliciousInput = "<script>alert('XSS')</script>";
        
        // Act
        string sanitized = InputSanitizer.SanitizeForXss(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("<script>"));
        Assert.That(sanitized, Does.Not.Contain("</script>"));
        Assert.That(sanitized, Does.Contain("&lt;script&gt;"));
    }

    [Test]
    public void Test_SanitizeForXss_EncodesSpecialCharacters()
    {
        // Arrange
        string input = "<>&\"'/";
        
        // Act
        string sanitized = InputSanitizer.SanitizeForXss(input);
        
        // Assert
        Assert.That(sanitized, Is.EqualTo("&lt;&gt;&amp;&quot;&#x27;&#x2F;"));
    }

    [Test]
    public void Test_SanitizeForXss_HandlesNullAndEmpty()
    {
        // Act & Assert
        Assert.That(InputSanitizer.SanitizeForXss(null), Is.Null);
        Assert.That(InputSanitizer.SanitizeForXss(""), Is.EqualTo(""));
    }

    [Test]
    public void Test_ContainsSqlInjectionPattern_DetectsSqlKeywords()
    {
        // Arrange & Act & Assert
        Assert.That(InputSanitizer.ContainsSqlInjectionPattern("admin' OR '1'='1"), Is.True);
        Assert.That(InputSanitizer.ContainsSqlInjectionPattern("SELECT * FROM Users"), Is.True);
        Assert.That(InputSanitizer.ContainsSqlInjectionPattern("'; DROP TABLE Users; --"), Is.True);
        Assert.That(InputSanitizer.ContainsSqlInjectionPattern("admin'--"), Is.True);
        Assert.That(InputSanitizer.ContainsSqlInjectionPattern("1' UNION SELECT"), Is.True);
    }

    [Test]
    public void Test_ContainsSqlInjectionPattern_AllowsNormalInput()
    {
        // Arrange & Act & Assert
        Assert.That(InputSanitizer.ContainsSqlInjectionPattern("john_doe"), Is.False);
        Assert.That(InputSanitizer.ContainsSqlInjectionPattern("user@example.com"), Is.False);
        Assert.That(InputSanitizer.ContainsSqlInjectionPattern("normaltext123"), Is.False);
    }

    [Test]
    public void Test_IsValidEmail_AcceptsValidEmails()
    {
        // Arrange & Act & Assert
        Assert.That(InputSanitizer.IsValidEmail("user@example.com"), Is.True);
        Assert.That(InputSanitizer.IsValidEmail("test.user@domain.co.uk"), Is.True);
        Assert.That(InputSanitizer.IsValidEmail("name+tag@example.com"), Is.True);
    }

    [Test]
    public void Test_IsValidEmail_RejectsInvalidEmails()
    {
        // Arrange & Act & Assert
        Assert.That(InputSanitizer.IsValidEmail("notanemail"), Is.False);
        Assert.That(InputSanitizer.IsValidEmail("@example.com"), Is.False);
        Assert.That(InputSanitizer.IsValidEmail("user@"), Is.False);
        Assert.That(InputSanitizer.IsValidEmail(""), Is.False);
        Assert.That(InputSanitizer.IsValidEmail(null), Is.False);
    }

    [Test]
    public void Test_IsValidUsername_AcceptsValidUsernames()
    {
        // Arrange & Act & Assert
        Assert.That(InputSanitizer.IsValidUsername("john_doe"), Is.True);
        Assert.That(InputSanitizer.IsValidUsername("user123"), Is.True);
        Assert.That(InputSanitizer.IsValidUsername("admin"), Is.True);
        Assert.That(InputSanitizer.IsValidUsername("test_user_123"), Is.True);
    }

    [Test]
    public void Test_IsValidUsername_RejectsInvalidUsernames()
    {
        // Arrange & Act & Assert
        Assert.That(InputSanitizer.IsValidUsername("ab"), Is.False); // Too short
        Assert.That(InputSanitizer.IsValidUsername("a".PadRight(21, 'a')), Is.False); // Too long
        Assert.That(InputSanitizer.IsValidUsername("user@name"), Is.False); // Invalid char
        Assert.That(InputSanitizer.IsValidUsername("user name"), Is.False); // Space
        Assert.That(InputSanitizer.IsValidUsername("user-name"), Is.False); // Hyphen
        Assert.That(InputSanitizer.IsValidUsername(""), Is.False);
        Assert.That(InputSanitizer.IsValidUsername(null), Is.False);
    }

    [Test]
    public void Test_SanitizeForSql_RemovesDangerousCharacters()
    {
        // Arrange
        string input = "test'; DROP TABLE--";
        
        // Act
        string sanitized = InputSanitizer.SanitizeForSql(input);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain(";"));
        Assert.That(sanitized, Does.Not.Contain("--"));
    }

    [Test]
    public void Test_XssAttackVectors_AreBlocked()
    {
        // Test various XSS attack vectors with HTML tags
        string[] xssVectors = new[]
        {
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<script>document.cookie</script>"
        };

        foreach (var vector in xssVectors)
        {
            string sanitized = InputSanitizer.SanitizeForXss(vector);
            // Verify dangerous tags are encoded (< and > are converted)
            Assert.That(sanitized, Does.Not.Contain("<script>"));
            Assert.That(sanitized, Does.Not.Contain("<iframe>"));
            Assert.That(sanitized, Does.Not.Contain("<svg"));
            // All angle brackets should be encoded
            Assert.That(sanitized, Does.Contain("&lt;"));
        }
        
        // Test non-HTML XSS vector separately
        string jsVector = "javascript:alert('XSS')";
        string sanitizedJs = InputSanitizer.SanitizeForXss(jsVector);
        Assert.That(sanitizedJs, Does.Contain("&#x27;")); // Quotes are encoded
    }
}
