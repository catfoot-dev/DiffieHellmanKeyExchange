using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace DiffieHellmanDemo.Api.Services;

/// <summary>
/// JWT 서명과 검증에 필요한 issuer, audience, 대칭키 설정을 보관합니다.
/// </summary>
public sealed class JwtSigningOptions
{
    /// <summary>
    /// 데모 서버 실행 동안 사용할 임시 대칭 서명 키를 생성합니다.
    /// </summary>
    public JwtSigningOptions()
    {
        var keyBytes = RandomNumberGenerator.GetBytes(32);
        SecurityKey = new SymmetricSecurityKey(keyBytes);
        SigningCredentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.HmacSha256);
    }

    public string Issuer { get; } = "DiffieHellmanDemo.Api";

    public string Audience { get; } = "DiffieHellmanDemo.Client";

    public SymmetricSecurityKey SecurityKey { get; }

    public SigningCredentials SigningCredentials { get; }

    /// <summary>
    /// 현재 서명 설정에 맞는 JWT 검증 파라미터를 생성합니다.
    /// </summary>
    /// <returns>issuer, audience, 서명 키, 수명 검증 규칙이 포함된 검증 파라미터입니다.</returns>
    public TokenValidationParameters CreateValidationParameters() =>
        new()
        {
            ValidateIssuer = true,
            ValidIssuer = Issuer,
            ValidateAudience = true,
            ValidAudience = Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = SecurityKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            NameClaimType = ClaimTypes.Name
        };
}
