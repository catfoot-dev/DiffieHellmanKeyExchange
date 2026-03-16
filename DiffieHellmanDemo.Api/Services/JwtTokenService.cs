using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using DiffieHellmanDemo.Common.Contracts;
using DiffieHellmanDemo.Common.Crypto;

namespace DiffieHellmanDemo.Api.Services;

/// <summary>
/// 세션과 사용자 정보를 기반으로 JWT와 로그인 응답 모델을 발급합니다.
/// </summary>
public sealed class JwtTokenService
{
    private readonly JwtSigningOptions _jwtSigningOptions;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// 서명 설정과 시간 공급자를 받아 토큰 발급 서비스를 초기화합니다.
    /// </summary>
    /// <param name="jwtSigningOptions">JWT 서명과 검증에 사용할 공통 설정입니다.</param>
    /// <param name="timeProvider">토큰 발급 시각과 만료 시각 계산에 사용할 시간 공급자입니다.</param>
    public JwtTokenService(JwtSigningOptions jwtSigningOptions, TimeProvider timeProvider)
    {
        _jwtSigningOptions = jwtSigningOptions;
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// 사용자 이름과 세션 식별자를 포함한 JWT를 발급하고 로그인 응답 모델로 감쌉니다.
    /// </summary>
    /// <param name="userName">토큰의 주체로 기록할 사용자 이름입니다.</param>
    /// <param name="sessionId">JWT의 <c>sid</c> 클레임으로 기록할 세션 식별자입니다.</param>
    /// <param name="sessionExpiresAtUtc">토큰 수명이 넘지 말아야 할 세션 만료 시각입니다.</param>
    /// <returns>서명된 액세스 토큰과 만료 시각을 담은 로그인 결과입니다.</returns>
    public LoginResult CreateLoginResult(string userName, string sessionId, DateTimeOffset sessionExpiresAtUtc)
    {
        var now = _timeProvider.GetUtcNow();
        var expiresAtUtc = now.Add(ProtocolConstants.MaxJwtLifetime);
        if (expiresAtUtc > sessionExpiresAtUtc)
        {
            expiresAtUtc = sessionExpiresAtUtc;
        }

        if (expiresAtUtc <= now)
        {
            throw new ProtocolFailureException(
                StatusCodes.Status410Gone,
                "Session expired",
                "The encrypted session expired before a JWT could be issued.");
        }

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userName),
            new Claim(ClaimTypes.Name, userName),
            new Claim("sid", sessionId),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
        };

        var token = new JwtSecurityToken(
            issuer: _jwtSigningOptions.Issuer,
            audience: _jwtSigningOptions.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expiresAtUtc.UtcDateTime,
            signingCredentials: _jwtSigningOptions.SigningCredentials);

        return new LoginResult
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
            ExpiresAtUtc = expiresAtUtc.ToUnixTimeMilliseconds(),
            UserName = userName
        };
    }
}
