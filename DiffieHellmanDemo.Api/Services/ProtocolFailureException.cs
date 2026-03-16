namespace DiffieHellmanDemo.Api.Services;

/// <summary>
/// 프로토콜 처리 중 발생한 도메인 오류를 HTTP 상태 코드와 함께 전달하는 예외입니다.
/// </summary>
public sealed class ProtocolFailureException : Exception
{
    /// <summary>
    /// 상태 코드와 제목을 포함한 프로토콜 예외를 생성합니다.
    /// </summary>
    /// <param name="statusCode">클라이언트에 반환할 HTTP 상태 코드입니다.</param>
    /// <param name="title">ProblemDetails의 제목으로 노출할 짧은 오류 요약입니다.</param>
    /// <param name="message">예외 본문과 detail에 사용할 상세 메시지입니다.</param>
    public ProtocolFailureException(int statusCode, string title, string message)
        : base(message)
    {
        StatusCode = statusCode;
        Title = title;
    }

    public int StatusCode { get; }

    public string Title { get; }
}
