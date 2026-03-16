namespace DiffieHellmanDemo.Api.Services;

/// <summary>
/// 인메모리 데모 계정 컬렉션을 사용해 자격 증명을 검증합니다.
/// </summary>
public sealed class DemoUserService
{
    private static readonly IReadOnlyDictionary<string, DemoUser> Users =
        new Dictionary<string, DemoUser>(StringComparer.OrdinalIgnoreCase)
        {
            ["alice"] = new("alice", "password123!"),
            ["bob"] = new("bob", "password456!")
        };

    /// <summary>
    /// 사용자 이름과 비밀번호가 데모 계정과 일치하는지 확인합니다.
    /// </summary>
    /// <param name="username">검증할 사용자 이름입니다.</param>
    /// <param name="password">사용자 이름과 함께 확인할 평문 비밀번호입니다.</param>
    /// <param name="user">검증 성공 시 일치한 데모 사용자 정보를 반환합니다.</param>
    /// <returns>자격 증명이 유효하면 <see langword="true"/>, 아니면 <see langword="false"/>입니다.</returns>
    public bool TryValidateCredentials(string username, string password, out DemoUser user)
    {
        if (string.IsNullOrWhiteSpace(username) ||
            string.IsNullOrWhiteSpace(password) ||
            !Users.TryGetValue(username, out var candidate) ||
            !string.Equals(candidate.Password, password, StringComparison.Ordinal))
        {
            user = default!;
            return false;
        }

        user = candidate;
        return true;
    }
}

/// <summary>
/// 데모 로그인에 사용할 인메모리 사용자 정보를 표현합니다.
/// </summary>
/// <param name="UserName">로그인 식별자로 사용할 사용자 이름입니다.</param>
/// <param name="Password">해당 사용자와 매칭되는 데모용 평문 비밀번호입니다.</param>
public sealed record DemoUser(string UserName, string Password);
