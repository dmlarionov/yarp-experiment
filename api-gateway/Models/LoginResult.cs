using System;
using System.Security.Claims;

namespace ApiGateway.Models
{
	public class LoginResult
	{
        public string Code { get; set; } = string.Empty;
        public string Explanation { get; set; } = string.Empty;
        public IEnumerable<Claim> Claims { get; set; } = new List<Claim>();
    }
}

