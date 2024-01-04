using System;
using System.Security.Claims;

namespace AuthorizationService.Models
{
	public record User(
		string Username,
		string Password,
		List<Claim>? Claims,
		string[]? Permissions);
}

