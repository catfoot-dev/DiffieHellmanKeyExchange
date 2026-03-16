namespace DiffieHellmanDemo.Api.Services;

/// <summary>
/// 서버 CLI 실행 시 부팅 단계와 프로토콜 처리 진행상태를 사람이 읽기 쉬운 콘솔 출력으로 기록합니다.
/// </summary>
internal sealed class ServerProgressReporter
{
    private readonly object _gate = new();
    private readonly bool _enabled;

    /// <summary>
    /// 현재 환경에서 진행상태 출력을 활성화할지 여부를 받아 출력기를 초기화합니다.
    /// </summary>
    /// <param name="enabled">콘솔 출력이 활성화되어야 하면 <see langword="true"/>입니다.</param>
    public ServerProgressReporter(bool enabled)
    {
        _enabled = enabled;
    }

    /// <summary>
    /// 지정한 workflow의 단계 메시지와 상세 정보를 콘솔에 출력합니다.
    /// </summary>
    /// <param name="workflow">로그가 속한 흐름 이름입니다. 예: <c>server</c>, <c>handshake</c>, <c>login</c>.</param>
    /// <param name="step">해당 흐름 안에서의 단계 번호입니다.</param>
    /// <param name="message">사람이 읽는 요약 메시지입니다.</param>
    /// <param name="details">들여쓰기된 별도 줄로 출력할 상세 정보 목록입니다.</param>
    public void ReportStep(string workflow, int step, string message, params string[] details)
    {
        if (!_enabled)
        {
            return;
        }

        lock (_gate)
        {
            Console.WriteLine($"[{workflow}] {step}. {message}");

            foreach (var detail in details)
            {
                if (!string.IsNullOrWhiteSpace(detail))
                {
                    foreach (var line in detail.ReplaceLineEndings("\n").Split('\n'))
                    {
                        if (!string.IsNullOrWhiteSpace(line))
                        {
                            Console.WriteLine($"   {line}");
                        }
                    }
                }
            }
        }
    }
}
