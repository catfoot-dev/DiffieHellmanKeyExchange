namespace DiffieHellmanDemo.Client;

/// <summary>
/// CLI 데모의 진입점을 제공합니다.
/// </summary>
public static class Program
{
    /// <summary>
    /// 옵션 없는 interactive 데모 실행을 시작합니다.
    /// </summary>
    /// <param name="args">전달된 명령줄 인자입니다. 현재는 비어 있어야 합니다.</param>
    /// <returns>성공 시 0, 실행 실패 시 0이 아닌 종료 코드를 담은 작업입니다.</returns>
    public static async Task<int> Main(string[] args)
    {
        var reporter = new ClientProgressReporter();

        if (args.Length > 0)
        {
            reporter.ReportStep(
                "client",
                0,
                "지원되지 않는 인자가 전달되었습니다.",
                "이 클라이언트는 옵션 없이 실행해야 합니다.");
            return 1;
        }

        try
        {
            await DemoClientRunner.RunAsync();
            return 0;
        }
        catch (Exception ex)
        {
            reporter.ReportStep(
                "client",
                0,
                "데모 실행에 실패했습니다.",
                ex.Message);
            return 1;
        }
    }
}
