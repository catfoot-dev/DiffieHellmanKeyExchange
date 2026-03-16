namespace DiffieHellmanDemo.Client;

/// <summary>
/// 클라이언트 시작 시 입력받는 로그인 자격 증명을 보관합니다.
/// </summary>
/// <param name="Username">암호화된 로그인 요청에 사용할 사용자 이름입니다.</param>
/// <param name="Password">암호화된 로그인 요청에 사용할 비밀번호입니다.</param>
internal sealed record ClientPromptValues(string Username, string Password);
