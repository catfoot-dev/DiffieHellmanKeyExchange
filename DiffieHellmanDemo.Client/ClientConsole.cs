namespace DiffieHellmanDemo.Client;

/// <summary>
/// 클라이언트 입력/출력 로직이 시스템 콘솔에 직접 결합되지 않도록 추상화한 인터페이스입니다.
/// </summary>
internal interface IClientConsole
{
    /// <summary>
    /// 현재 입력이 터미널이 아닌 리다이렉션 상태인지 나타냅니다.
    /// </summary>
    bool IsInputRedirected { get; }

    /// <summary>
    /// 프롬프트를 줄바꿈 없이 출력합니다.
    /// </summary>
    /// <param name="value">출력할 문자열입니다.</param>
    void Write(string value);

    /// <summary>
    /// 한 줄의 입력을 읽습니다.
    /// </summary>
    /// <returns>입력된 문자열 또는 EOF인 경우 <see langword="null"/>입니다.</returns>
    string? ReadLine();
}

/// <summary>
/// 실제 시스템 콘솔을 사용하는 기본 <see cref="IClientConsole"/> 구현입니다.
/// </summary>
internal sealed class SystemClientConsole : IClientConsole
{
    /// <inheritdoc />
    public bool IsInputRedirected => Console.IsInputRedirected;

    /// <inheritdoc />
    public void Write(string value) => Console.Write(value);

    /// <inheritdoc />
    public string? ReadLine() => Console.ReadLine();
}
