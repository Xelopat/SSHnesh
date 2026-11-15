using System.Text;
using System.Windows.Forms;

static class SecretDialog
{
    private sealed record WindowOwner(nint Handle) : IWin32Window;

    internal static int Ask(string caption, nint owner)
    {
        var result = 1;
        var ui = new Thread(() =>
        {
            Application.EnableVisualStyles();
            using var window = new Form {
                Text = "SSHnesh — " + caption, Width = 460, Height = 148,
                StartPosition = owner == 0 ? FormStartPosition.CenterScreen : FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MinimizeBox = false, MaximizeBox = false, ShowInTaskbar = owner == 0
            };
            var secret = new TextBox {
                Left = 14, Top = 15, Width = 414, MaxLength = 4096,
                UseSystemPasswordChar = true, AccessibleName = caption
            };
            var ok = new Button { Text = "Принять", Left = 244, Top = 53, Width = 86, Enabled = false, DialogResult = DialogResult.OK };
            var cancel = new Button { Text = "Отмена", Left = 340, Top = 53, Width = 86, DialogResult = DialogResult.Cancel };
            secret.TextChanged += (_, _) => ok.Enabled = secret.TextLength > 0;
            window.Controls.AddRange([secret, ok, cancel]);
            window.AcceptButton = ok;
            window.CancelButton = cancel;
            window.ActiveControl = secret;
            window.Shown += (_, _) => {
                window.Activate();
                secret.Focus();
            };
            if (window.ShowDialog(owner == 0 ? null : new WindowOwner(owner)) == DialogResult.OK)
            {
                Console.OutputEncoding = new UTF8Encoding(false);
                Console.Out.Write(secret.Text);
                Console.Out.Flush();
                result = 0;
            }
            secret.Clear();
        });
        ui.SetApartmentState(ApartmentState.STA);
        ui.Start();
        ui.Join();
        return result;
    }
}
