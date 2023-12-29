using System;
using Microsoft.AspNetCore.DataProtection;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Distributed.Authentication
{
	public static class TicketProtection
	{
        public static string Protect(IDataProtector protector, byte[] data)
        {
            var protectedData = protector.Protect(data);
            return Convert.ToBase64String(protectedData).TrimEnd('=');
        }

        public static byte[] Unprotect(IDataProtector protector, string protectedText)
        {
            var protectedData = Convert.FromBase64String(Pad(protectedText));
            return protector.Unprotect(protectedData);
        }

        private static string Pad(string text)
        {
            var padding = 3 - ((text.Length + 3) % 4);
            if (padding == 0)
            {
                return text;
            }
            return text + new string('=', padding);
        }
    }
}

