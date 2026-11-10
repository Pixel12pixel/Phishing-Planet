using MimeKit;

namespace Phishing_Planet.Presentation;

public interface IEmailPresenter
{
    void ShowInfo(string message);
    void ShowError(Exception exception);
    void ShowEmail(MimeMessage message);
}