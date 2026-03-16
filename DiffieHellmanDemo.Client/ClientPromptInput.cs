namespace DiffieHellmanDemo.Client;

/// <summary>
/// interactive 클라이언트 실행에 필요한 계정, 비밀번호, 메시지, 단계 진행 입력을 수집합니다.
/// </summary>
internal sealed class ClientPromptInput
{
    private readonly IClientConsole _console;
    private readonly ClientProgressReporter _reporter;

    /// <summary>
    /// 콘솔 입출력과 reporter를 받아 입력 수집기를 초기화합니다.
    /// </summary>
    /// <param name="console">실제 입력을 읽어 올 콘솔 추상화입니다.</param>
    /// <param name="reporter">프롬프트 단계 로그를 출력할 reporter입니다.</param>
    public ClientPromptInput(IClientConsole console, ClientProgressReporter reporter)
    {
        _console = console;
        _reporter = reporter;
    }

    /// <summary>
    /// 로그인에 사용할 계정과 비밀번호를 순서대로 입력받습니다.
    /// </summary>
    /// <returns>사용자가 입력한 로그인 자격 증명입니다.</returns>
    public ClientPromptValues PromptForCredentials()
    {
        EnsureInteractiveInput();

        _reporter.ReportStep(
            "client",
            2,
            "로그인 정보를 입력합니다.",
            "서버 로그인에 사용할 계정과 비밀번호를 입력하세요.");

        var username = ReadRequiredLine("   username> ", "계정은 비워 둘 수 없습니다.");
        var password = ReadRequiredLine("   password> ", "비밀번호는 비워 둘 수 없습니다.");

        return new ClientPromptValues(username, password);
    }

    /// <summary>
    /// echo 단계에서 서버로 보낼 다음 메시지를 입력받습니다.
    /// </summary>
    /// <returns>사용자가 입력한 메시지입니다. 빈 문자열도 정상 메시지로 반환됩니다.</returns>
    public string PromptForEchoMessage()
    {
        EnsureInteractiveInput();

        _reporter.ReportStep(
            "echo",
            0,
            "전송할 메시지를 입력하세요.",
            "종료하려면 정확히 quit 를 입력하세요.");

        _console.Write("   message> ");
        return _console.ReadLine()
            ?? throw new InvalidOperationException("메시지 입력을 읽지 못했습니다.");
    }

    /// <summary>
    /// 사용자가 Enter를 눌러야 다음 큰 단계로 진행하도록 대기합니다.
    /// </summary>
    /// <param name="workflow">로그가 속한 workflow 이름입니다.</param>
    /// <param name="step">대기 안내를 출력할 단계 번호입니다.</param>
    /// <param name="nextStageDescription">Enter 이후 진행할 다음 단계 설명입니다.</param>
    public void WaitForEnter(string workflow, int step, string nextStageDescription)
    {
        EnsureInteractiveInput();

        _reporter.ReportStep(
            workflow,
            step,
            "다음 단계로 진행할 준비가 되었습니다.",
            $"Enter를 누르면 {nextStageDescription}");

        _console.Write("   > ");
        _ = _console.ReadLine()
            ?? throw new InvalidOperationException("다음 단계 진행 입력을 읽지 못했습니다.");
    }

    private string ReadRequiredLine(string prompt, string errorMessage)
    {
        _console.Write(prompt);
        var value = _console.ReadLine()
            ?? throw new InvalidOperationException("콘솔 입력을 읽지 못했습니다.");

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException(errorMessage);
        }

        return value;
    }

    private void EnsureInteractiveInput()
    {
        if (_console.IsInputRedirected)
        {
            throw new InvalidOperationException("interactive 입력이 필요하지만 stdin이 터미널이 아닙니다.");
        }
    }
}
