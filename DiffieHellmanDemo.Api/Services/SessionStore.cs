using System.Collections.Concurrent;
using DiffieHellmanDemo.Common.Crypto;

namespace DiffieHellmanDemo.Api.Services;

/// <summary>
/// 메모리 안에 활성 암호화 세션을 저장하고 조회하는 저장소입니다.
/// </summary>
public sealed class SessionStore
{
    private readonly ConcurrentDictionary<string, SessionState> _sessions = new();
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// 세션 만료 판정에 사용할 시간 공급자를 받아 저장소를 초기화합니다.
    /// </summary>
    /// <param name="timeProvider">현재 UTC 시각을 조회하는 시간 공급자입니다.</param>
    public SessionStore(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// 새 세션 식별자와 만료 시각을 생성해 메모리 저장소에 등록합니다.
    /// </summary>
    /// <param name="sessionSecrets">세션 공유 비밀에서 파생한 방향별 키 재료입니다.</param>
    /// <returns>저장소에 등록된 활성 세션 상태입니다.</returns>
    public SessionState CreateSession(SessionSecrets sessionSecrets)
    {
        var now = _timeProvider.GetUtcNow();
        var session = new SessionState(
            Guid.NewGuid().ToString("N"),
            now.Add(ProtocolConstants.SessionTtl),
            sessionSecrets,
            _timeProvider);

        _sessions[session.SessionId] = session;
        return session;
    }

    /// <summary>
    /// 세션 식별자로 활성 세션을 조회하고, 없거나 만료된 경우 프로토콜 예외를 발생시킵니다.
    /// </summary>
    /// <param name="sessionId">조회할 세션 식별자입니다.</param>
    /// <returns>현재 사용 가능한 세션 상태입니다.</returns>
    public SessionState GetRequired(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            throw new ProtocolFailureException(
                StatusCodes.Status400BadRequest,
                "Missing session",
                "The encrypted envelope did not contain a session id.");
        }

        if (!_sessions.TryGetValue(sessionId, out var session))
        {
            throw new ProtocolFailureException(
                StatusCodes.Status410Gone,
                "Session expired",
                "The encrypted session does not exist or has already expired.");
        }

        if (!session.IsExpired())
        {
            return session;
        }

        _sessions.TryRemove(sessionId, out _);
        throw new ProtocolFailureException(
            StatusCodes.Status410Gone,
            "Session expired",
            "The encrypted session is no longer active.");
    }

    /// <summary>
    /// 지정한 세션을 저장소에서 제거해 강제로 만료시킵니다.
    /// </summary>
    /// <param name="sessionId">제거할 세션 식별자입니다.</param>
    /// <returns>세션이 실제로 제거되었으면 <see langword="true"/>, 없었다면 <see langword="false"/>입니다.</returns>
    public bool ExpireSession(string sessionId) =>
        _sessions.TryRemove(sessionId, out _);
}
