using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuthentication
{
    public class JWTAuthenticationManager : IJWTAuthenticationManager
    {
        private readonly IDictionary<string, string> users = new Dictionary<string, string> { { "user1", "pass1" }, { "user2", "pass2" } };
        private readonly string key;

        public JWTAuthenticationManager(string key)
        {
            this.key = key;
        }

        public string Authenticate(string userName, string password)
        {
            return GetToken();
            
            if (!users.Any(x => x.Key == userName && x.Value == password))
            {
                return null;
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(key);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[] {
                    new Claim(ClaimTypes.Name, userName)
                }),
                Expires = DateTime.UtcNow.AddMinutes(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey),
                SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public string GetToken()
        {
            var issuer = "http://mysite.com";
            var securitKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key));
            var credentials = new SigningCredentials(securitKey, SecurityAlgorithms.HmacSha256);

            var permClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("valid", "1"),
                new Claim("userId", "1"),
                new Claim("name", "Tanveer")
            };

            var token = new JwtSecurityToken(issuer,
                issuer,
                permClaims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: credentials
                );

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            return jwtToken;
        }
    }
}
