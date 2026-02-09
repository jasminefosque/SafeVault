using NUnit.Framework;
using SafeVault.App.Models;
using SafeVault.App.Security;

namespace Tests;

[TestFixture]
public class TestAuthorization
{
    private User _adminUser = null!;
    private User _regularUser = null!;

    [SetUp]
    public void Setup()
    {
        _adminUser = new User
        {
            Id = 1,
            Username = "admin",
            Email = "admin@safevault.com",
            PasswordHash = AuthService.HashPassword("AdminPass123!"),
            Role = "admin"
        };

        _regularUser = new User
        {
            Id = 2,
            Username = "john_doe",
            Email = "john@example.com",
            PasswordHash = AuthService.HashPassword("UserPass123!"),
            Role = "user"
        };
    }

    [Test]
    public void Test_HasRole_AdminUser()
    {
        // Act & Assert
        Assert.That(RoleAuthorization.HasRole(_adminUser, "admin"), Is.True);
        Assert.That(RoleAuthorization.HasRole(_adminUser, "user"), Is.False);
    }

    [Test]
    public void Test_HasRole_RegularUser()
    {
        // Act & Assert
        Assert.That(RoleAuthorization.HasRole(_regularUser, "user"), Is.True);
        Assert.That(RoleAuthorization.HasRole(_regularUser, "admin"), Is.False);
    }

    [Test]
    public void Test_HasRole_CaseInsensitive()
    {
        // Act & Assert
        Assert.That(RoleAuthorization.HasRole(_adminUser, "ADMIN"), Is.True);
        Assert.That(RoleAuthorization.HasRole(_adminUser, "Admin"), Is.True);
        Assert.That(RoleAuthorization.HasRole(_regularUser, "USER"), Is.True);
    }

    [Test]
    public void Test_HasRole_NullUser()
    {
        // Act & Assert
        Assert.That(RoleAuthorization.HasRole(null!, "admin"), Is.False);
    }

    [Test]
    public void Test_IsAdmin_AdminUser()
    {
        // Act & Assert
        Assert.That(RoleAuthorization.IsAdmin(_adminUser), Is.True);
    }

    [Test]
    public void Test_IsAdmin_RegularUser()
    {
        // Act & Assert
        Assert.That(RoleAuthorization.IsAdmin(_regularUser), Is.False);
    }

    [Test]
    public void Test_IsUser_RegularUser()
    {
        // Act & Assert
        Assert.That(RoleAuthorization.IsUser(_regularUser), Is.True);
    }

    [Test]
    public void Test_IsUser_AdminUser()
    {
        // Act & Assert
        Assert.That(RoleAuthorization.IsUser(_adminUser), Is.False);
    }

    [Test]
    public void Test_RequireRole_Success()
    {
        // Act & Assert - Should not throw
        Assert.DoesNotThrow(() => RoleAuthorization.RequireRole(_adminUser, "admin"));
        Assert.DoesNotThrow(() => RoleAuthorization.RequireRole(_regularUser, "user"));
    }

    [Test]
    public void Test_RequireRole_Failure()
    {
        // Act & Assert
        var ex1 = Assert.Throws<UnauthorizedAccessException>(() =>
            RoleAuthorization.RequireRole(_regularUser, "admin"));
        Assert.That(ex1!.Message, Does.Contain("admin"));

        var ex2 = Assert.Throws<UnauthorizedAccessException>(() =>
            RoleAuthorization.RequireRole(_adminUser, "user"));
        Assert.That(ex2!.Message, Does.Contain("user"));
    }

    [Test]
    public void Test_RequireAdmin_AdminUser()
    {
        // Act & Assert - Should not throw
        Assert.DoesNotThrow(() => RoleAuthorization.RequireAdmin(_adminUser));
    }

    [Test]
    public void Test_RequireAdmin_RegularUser()
    {
        // Act & Assert
        var ex = Assert.Throws<UnauthorizedAccessException>(() =>
            RoleAuthorization.RequireAdmin(_regularUser));
        Assert.That(ex!.Message, Does.Contain("admin"));
    }

    [Test]
    public void Test_CanAccessResource_AdminCanAccessAll()
    {
        // Act & Assert
        Assert.That(RoleAuthorization.CanAccessResource(_adminUser, 1), Is.True);
        Assert.That(RoleAuthorization.CanAccessResource(_adminUser, 2), Is.True);
        Assert.That(RoleAuthorization.CanAccessResource(_adminUser, 999), Is.True);
    }

    [Test]
    public void Test_CanAccessResource_UserCanAccessOwn()
    {
        // Act & Assert
        Assert.That(RoleAuthorization.CanAccessResource(_regularUser, 2), Is.True); // Own resource
        Assert.That(RoleAuthorization.CanAccessResource(_regularUser, 1), Is.False); // Other's resource
        Assert.That(RoleAuthorization.CanAccessResource(_regularUser, 999), Is.False); // Other's resource
    }

    [Test]
    public void Test_CanAccessResource_NullUser()
    {
        // Act & Assert
        Assert.That(RoleAuthorization.CanAccessResource(null!, 1), Is.False);
    }

    [Test]
    public void Test_PrivilegeEscalation_Prevention()
    {
        // Arrange
        var maliciousUser = new User
        {
            Id = 3,
            Username = "hacker",
            Email = "hacker@example.com",
            PasswordHash = AuthService.HashPassword("HackerPass123!"),
            Role = "user" // Try to escalate to admin
        };

        // Act - Try to access admin resources
        bool canAccessAdminResource = RoleAuthorization.CanAccessResource(maliciousUser, 1);
        bool isAdmin = RoleAuthorization.IsAdmin(maliciousUser);

        // Assert
        Assert.That(canAccessAdminResource, Is.False);
        Assert.That(isAdmin, Is.False);
        Assert.Throws<UnauthorizedAccessException>(() =>
            RoleAuthorization.RequireAdmin(maliciousUser));
    }

    [Test]
    public void Test_Authorization_ConsistentBehavior()
    {
        // Verify that multiple checks return consistent results
        for (int i = 0; i < 5; i++)
        {
            Assert.That(RoleAuthorization.IsAdmin(_adminUser), Is.True);
            Assert.That(RoleAuthorization.IsAdmin(_regularUser), Is.False);
            Assert.That(RoleAuthorization.CanAccessResource(_adminUser, 999), Is.True);
            Assert.That(RoleAuthorization.CanAccessResource(_regularUser, 999), Is.False);
        }
    }

    [Test]
    public void Test_RoleConstants()
    {
        // Verify role constants are correct
        Assert.That(RoleAuthorization.AdminRole, Is.EqualTo("admin"));
        Assert.That(RoleAuthorization.UserRole, Is.EqualTo("user"));
    }

    [Test]
    public void Test_MultipleUsers_IndependentAuthorization()
    {
        // Arrange
        var user1 = new User { Id = 10, Username = "user1", Role = "user" };
        var user2 = new User { Id = 20, Username = "user2", Role = "user" };
        var user3 = new User { Id = 30, Username = "user3", Role = "user" };

        // Act & Assert - Each user can only access their own resources
        Assert.That(RoleAuthorization.CanAccessResource(user1, 10), Is.True);
        Assert.That(RoleAuthorization.CanAccessResource(user1, 20), Is.False);
        Assert.That(RoleAuthorization.CanAccessResource(user1, 30), Is.False);

        Assert.That(RoleAuthorization.CanAccessResource(user2, 10), Is.False);
        Assert.That(RoleAuthorization.CanAccessResource(user2, 20), Is.True);
        Assert.That(RoleAuthorization.CanAccessResource(user2, 30), Is.False);

        Assert.That(RoleAuthorization.CanAccessResource(user3, 10), Is.False);
        Assert.That(RoleAuthorization.CanAccessResource(user3, 20), Is.False);
        Assert.That(RoleAuthorization.CanAccessResource(user3, 30), Is.True);
    }
}
