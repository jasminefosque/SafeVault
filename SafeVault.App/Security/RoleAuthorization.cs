using SafeVault.App.Models;

namespace SafeVault.App.Security;

/// <summary>
/// Provides role-based authorization checks
/// </summary>
public class RoleAuthorization
{
    public const string AdminRole = "admin";
    public const string UserRole = "user";

    /// <summary>
    /// Checks if a user has the specified role
    /// </summary>
    public static bool HasRole(User user, string role)
    {
        if (user == null || string.IsNullOrEmpty(role))
            return false;

        return user.Role.Equals(role, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Checks if a user is an administrator
    /// </summary>
    public static bool IsAdmin(User user)
    {
        return HasRole(user, AdminRole);
    }

    /// <summary>
    /// Checks if a user is a regular user
    /// </summary>
    public static bool IsUser(User user)
    {
        return HasRole(user, UserRole);
    }

    /// <summary>
    /// Authorizes access based on required role
    /// Throws UnauthorizedAccessException if user doesn't have the required role
    /// </summary>
    public static void RequireRole(User user, string requiredRole)
    {
        if (!HasRole(user, requiredRole))
        {
            throw new UnauthorizedAccessException($"User does not have the required role: {requiredRole}");
        }
    }

    /// <summary>
    /// Authorizes admin access
    /// Throws UnauthorizedAccessException if user is not an admin
    /// </summary>
    public static void RequireAdmin(User user)
    {
        RequireRole(user, AdminRole);
    }

    /// <summary>
    /// Checks if user can access a resource
    /// Admins can access everything, users can only access their own resources
    /// </summary>
    public static bool CanAccessResource(User user, int resourceOwnerId)
    {
        if (user == null)
            return false;

        // Admins can access everything
        if (IsAdmin(user))
            return true;

        // Users can only access their own resources
        return user.Id == resourceOwnerId;
    }
}
