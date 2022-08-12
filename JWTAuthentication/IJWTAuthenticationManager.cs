using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication
{
	public interface IJWTAuthenticationManager
	{
		string Authenticate(string userName, string password);
	}
}
