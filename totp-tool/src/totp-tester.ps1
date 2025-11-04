# Validate-TOTP-WithQR.ps1
# PowerShell 5.x WinForms app: TOTP generator/validator + QR decode via ZXing (no System.Net.Http required)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------- Embedded C# helper for robust TOTP + otpauth parsing ----------
$cs = @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

public static class TotpHelper
{
    public enum HashAlgo { SHA1, SHA256, SHA512 }

    public static byte[] Base32Decode(string input)
    {
        if (input == null) throw new ArgumentNullException("input");
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var cleanSb = new StringBuilder();
        foreach (char c in input)
        {
            if (c == '=' || Char.IsWhiteSpace(c)) continue;
            cleanSb.Append(Char.ToUpperInvariant(c));
        }
        string clean = cleanSb.ToString();

        int buffer = 0, bitsLeft = 0;
        var bytes = new List<byte>((clean.Length * 5) / 8);
        foreach (char ch in clean)
        {
            int val = alphabet.IndexOf(ch);
            if (val < 0) throw new FormatException("Invalid Base32 char: " + ch);
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                bytes.Add((byte)((buffer >> bitsLeft) & 0xFF));
            }
        }
        return bytes.ToArray();
    }

    private static long GetTimeStep(DateTime utcNow, int periodSeconds)
    {
        var epoch = new DateTime(1970,1,1,0,0,0, DateTimeKind.Utc);
        long unix = (long)Math.Floor((utcNow - epoch).TotalSeconds);
        return unix / periodSeconds;
    }

    private static byte[] GetCounterBytes(long counter)
    {
        byte[] msg = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(msg);
        return msg;
    }

    private static byte[] ComputeHmac(byte[] key, byte[] msg, HashAlgo algo)
    {
        switch(algo)
        {
            case HashAlgo.SHA256: using (var h = new HMACSHA256(key)) return h.ComputeHash(msg);
            case HashAlgo.SHA512: using (var h = new HMACSHA512(key)) return h.ComputeHash(msg);
            default: using (var h = new HMACSHA1(key)) return h.ComputeHash(msg);
        }
    }

    private static int DynamicTruncate(byte[] hash)
    {
        int offset = hash[hash.Length - 1] & 0x0F;
        int binary =
              ((hash[offset] & 0x7F) << 24)
            | ((hash[offset + 1] & 0xFF) << 16)
            | ((hash[offset + 2] & 0xFF) << 8)
            |  (hash[offset + 3] & 0xFF);
        return binary;
    }

    private static int Pow10(int n)
    {
        int v = 1;
        for (int i = 0; i < n; i++) v *= 10;
        return v;
    }

    public static string Generate(string base32Secret, int digits, int periodSeconds, HashAlgo algo, DateTime? nowUtc)
    {
        if (base32Secret == null) throw new ArgumentNullException("base32Secret");
        if (digits < 1) throw new ArgumentOutOfRangeException("digits");
        byte[] key = Base32Decode(base32Secret);
        long timestep = GetTimeStep(nowUtc ?? DateTime.UtcNow, periodSeconds);
        byte[] msg = GetCounterBytes(timestep);
        byte[] hash = ComputeHmac(key, msg, algo);
        int binary = DynamicTruncate(hash);
        int otp = binary % Pow10(digits);
        return otp.ToString().PadLeft(digits, '0');
    }

    public static bool Validate(string base32Secret, string userCode, int digits, int periodSeconds, HashAlgo algo, int driftSteps, DateTime? nowUtc, out string matchedCode, out long matchedStep)
    {
        matchedCode = null; matchedStep = 0;
        if (string.IsNullOrEmpty(userCode)) return false;
        DateTime now = nowUtc ?? DateTime.UtcNow;
        long center = GetTimeStep(now, periodSeconds);
        byte[] key = Base32Decode(base32Secret);
        for (long s = center - driftSteps; s <= center + driftSteps; s++)
        {
            byte[] msg = GetCounterBytes(s);
            byte[] hash = ComputeHmac(key, msg, algo);
            int binary = DynamicTruncate(hash);
            int otp = binary % Pow10(digits);
            string candidate = otp.ToString().PadLeft(digits, '0');
            if (candidate == userCode)
            {
                matchedCode = candidate;
                matchedStep = s;
                return true;
            }
        }
        return false;
    }

    // Returns secret from otpauth URI or null
    public static string ExtractSecretFromOtpauthUri(string uri)
    {
        if (String.IsNullOrEmpty(uri)) return null;
        try
        {
            if (!uri.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase)) return null;
            var u = new Uri(uri);
            var qs = System.Web.HttpUtility.ParseQueryString(u.Query);
            var s = qs["secret"];
            if (String.IsNullOrEmpty(s)) return null;
            return s;
        }
        catch { return null; }
    }
}
"@
Add-Type -TypeDefinition $cs -ReferencedAssemblies @("System.Web","System.Security")

# ---------- UI ----------
$form = New-Object System.Windows.Forms.Form
$form.Text = "TOTP Validator (QR decode via ZXing)"
$form.Size = New-Object System.Drawing.Size(580,500)
$form.StartPosition = "CenterScreen"

$lblSecret = New-Object System.Windows.Forms.Label
$lblSecret.Text = "Base32 Secret or otpauth:// URI:"
$lblSecret.AutoSize = $true
$lblSecret.Location = New-Object System.Drawing.Point(10,15)
$form.Controls.Add($lblSecret)

$txtSecret = New-Object System.Windows.Forms.TextBox
$txtSecret.Size = New-Object System.Drawing.Size(540,22)
$txtSecret.Location = New-Object System.Drawing.Point(10,35)
$form.Controls.Add($txtSecret)

$btnQR = New-Object System.Windows.Forms.Button
$btnQR.Text = "Decode QR…"
$btnQR.Size = New-Object System.Drawing.Size(110,26)
$btnQR.Location = New-Object System.Drawing.Point(10,65)
$form.Controls.Add($btnQR)

$lblAlgo = New-Object System.Windows.Forms.Label
$lblAlgo.Text = "Algorithm:"
$lblAlgo.AutoSize = $true
$lblAlgo.Location = New-Object System.Drawing.Point(140,69)
$form.Controls.Add($lblAlgo)

$cmbAlgo = New-Object System.Windows.Forms.ComboBox
$cmbAlgo.Items.AddRange(@("SHA1","SHA256","SHA512"))
$cmbAlgo.DropDownStyle = "DropDownList"
$cmbAlgo.SelectedIndex = 0
$cmbAlgo.Location = New-Object System.Drawing.Point(200,66)
$cmbAlgo.Width = 90
$form.Controls.Add($cmbAlgo)

$lblDigits = New-Object System.Windows.Forms.Label
$lblDigits.Text = "Digits:"
$lblDigits.AutoSize = $true
$lblDigits.Location = New-Object System.Drawing.Point(300,69)
$form.Controls.Add($lblDigits)

$numDigits = New-Object System.Windows.Forms.NumericUpDown
$numDigits.Minimum = 4; $numDigits.Maximum = 8; $numDigits.Value = 6
$numDigits.Location = New-Object System.Drawing.Point(340,66)
$form.Controls.Add($numDigits)

$lblPeriod = New-Object System.Windows.Forms.Label
$lblPeriod.Text = "Period (sec):"
$lblPeriod.AutoSize = $true
$lblPeriod.Location = New-Object System.Drawing.Point(410,69)
$form.Controls.Add($lblPeriod)

$numPeriod = New-Object System.Windows.Forms.NumericUpDown
$numPeriod.Minimum = 10; $numPeriod.Maximum = 300; $numPeriod.Value = 30
$numPeriod.Location = New-Object System.Drawing.Point(490,66)
$form.Controls.Add($numPeriod)

$lblDrift = New-Object System.Windows.Forms.Label
$lblDrift.Text = "Drift (± steps):"
$lblDrift.AutoSize = $true
$lblDrift.Location = New-Object System.Drawing.Point(10,100)
$form.Controls.Add($lblDrift)

$numDrift = New-Object System.Windows.Forms.NumericUpDown
$numDrift.Minimum = 0; $numDrift.Maximum = 5; $numDrift.Value = 1
$numDrift.Location = New-Object System.Drawing.Point(100,98)
$form.Controls.Add($numDrift)

$lblCurrent = New-Object System.Windows.Forms.Label
$lblCurrent.Text = "Current TOTP:"
$lblCurrent.AutoSize = $true
$lblCurrent.Location = New-Object System.Drawing.Point(10,140)
$form.Controls.Add($lblCurrent)

$txtCurrent = New-Object System.Windows.Forms.TextBox
$txtCurrent.ReadOnly = $true
$txtCurrent.Font = New-Object System.Drawing.Font("Consolas",18,[System.Drawing.FontStyle]::Bold)
$txtCurrent.Size = New-Object System.Drawing.Size(240,44)
$txtCurrent.Location = New-Object System.Drawing.Point(10,160)
$form.Controls.Add($txtCurrent)

$lblCountdown = New-Object System.Windows.Forms.Label
$lblCountdown.Text = "Time left:"
$lblCountdown.AutoSize = $true
$lblCountdown.Location = New-Object System.Drawing.Point(270,150)
$form.Controls.Add($lblCountdown)

$txtCountdown = New-Object System.Windows.Forms.TextBox
$txtCountdown.ReadOnly = $true
$txtCountdown.Font = New-Object System.Drawing.Font("Consolas",14)
$txtCountdown.Size = New-Object System.Drawing.Size(140,34)
$txtCountdown.Location = New-Object System.Drawing.Point(270,170)
$form.Controls.Add($txtCountdown)

$lblToken = New-Object System.Windows.Forms.Label
$lblToken.Text = "Enter token to validate:"
$lblToken.AutoSize = $true
$lblToken.Location = New-Object System.Drawing.Point(10,220)
$form.Controls.Add($lblToken)

$txtToken = New-Object System.Windows.Forms.TextBox
$txtToken.Size = New-Object System.Drawing.Size(180,22)
$txtToken.Location = New-Object System.Drawing.Point(10,240)
$form.Controls.Add($txtToken)

$btnValidate = New-Object System.Windows.Forms.Button
$btnValidate.Text = "Validate"
$btnValidate.Size = New-Object System.Drawing.Size(100,28)
$btnValidate.Location = New-Object System.Drawing.Point(200,238)
$form.Controls.Add($btnValidate)

$lblResult = New-Object System.Windows.Forms.Label
$lblResult.Text = ""
$lblResult.AutoSize = $true
$lblResult.Location = New-Object System.Drawing.Point(10,275)
$lblResult.Font = New-Object System.Drawing.Font("Microsoft Sans Serif",10,[System.Drawing.FontStyle]::Bold)
$form.Controls.Add($lblResult)

$btnSample = New-Object System.Windows.Forms.Button
$btnSample.Text = "Fill sample secret"
$btnSample.Size = New-Object System.Drawing.Size(140,24)
$btnSample.Location = New-Object System.Drawing.Point(320,238)
$form.Controls.Add($btnSample)

# ---------- Helpers ----------
function Get-SecretOnly {
    param([string]$Text)
    $s = [TotpHelper]::ExtractSecretFromOtpauthUri($Text)
    if ([string]::IsNullOrEmpty($s)) { return $Text } else { return $s }
}

function Try-ApplyOtpUriParams {
    param([string]$UriText)
    try {
        if (-not $UriText.StartsWith("otpauth://",[StringComparison]::OrdinalIgnoreCase)) { return }
        $u  = [Uri]$UriText
        $qs = [System.Web.HttpUtility]::ParseQueryString($u.Query)
        if ($qs["algorithm"]) {
            switch -regex ($qs["algorithm"].ToUpperInvariant()) {
                "SHA256" { $cmbAlgo.SelectedItem = "SHA256" }
                "SHA512" { $cmbAlgo.SelectedItem = "SHA512" }
                default  { $cmbAlgo.SelectedItem = "SHA1" }
            }
        }
        if ($qs["digits"]) { [void][int]::TryParse($qs["digits"], [ref]([int]$numDigits.Value)); $numDigits.Value = [int]$qs["digits"] }
        if ($qs["period"]) { [void][int]::TryParse($qs["period"], [ref]([int]$numPeriod.Value)); $numPeriod.Value = [int]$qs["period"] }
    } catch { }
}

# ZXing HTML decoder via HttpWebRequest (multipart/form-data), no System.Net.Http dependency
function Invoke-DecodeQRViaZXing {
    param([string]$ImagePath)

    if (-not (Test-Path $ImagePath)) { throw "File not found: $ImagePath" }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $uri = 'https://zxing.org/w/decode'
    $boundary = "---------------------------" + ([Guid]::NewGuid().ToString("N"))
    $nl  = "`r`n"

    $fileBytes = [System.IO.File]::ReadAllBytes($ImagePath)
    $fileName  = [System.IO.Path]::GetFileName($ImagePath)

    $preFile  = "--$boundary$nl" +
                "Content-Disposition: form-data; name=`"f`"; filename=`"$fileName`"$nl" +
                "Content-Type: application/octet-stream$nl$nl"

    $postFile = "$nl--$boundary$nl" +
                "Content-Disposition: form-data; name=`"full`"$nl$nl" +
                "true$nl--$boundary--$nl"

    $preBytes  = [System.Text.Encoding]::ASCII.GetBytes($preFile)
    $postBytes = [System.Text.Encoding]::ASCII.GetBytes($postFile)

    $req = [System.Net.HttpWebRequest]::Create($uri)
    $req.Method      = "POST"
    $req.ContentType = "multipart/form-data; boundary=$boundary"
    $req.KeepAlive   = $false

    $stream = $req.GetRequestStream()
    try {
        $stream.Write($preBytes, 0, $preBytes.Length)
        $stream.Write($fileBytes, 0, $fileBytes.Length)
        $stream.Write($postBytes, 0, $postBytes.Length)
    } finally { $stream.Dispose() }

    $resp = $req.GetResponse()
    try {
        $sr   = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $html = $sr.ReadToEnd()
        $sr.Dispose()
    } finally { $resp.Dispose() }

    $decoded = [System.Web.HttpUtility]::HtmlDecode($html)
    if (-not $decoded) { throw "Empty ZXing response." }

    $m = [Regex]::Match($decoded, 'otpauth://[^\s<"]+', 'IgnoreCase')
    if ($m.Success) { return $m.Value }

    $m = [Regex]::Match($decoded, '(?s)Parsed Result.*?>(.*?)</', 'IgnoreCase')
    if ($m.Success) {
        $maybe = [System.Web.HttpUtility]::HtmlDecode($m.Groups[1].Value.Trim())
        if ($maybe -and $maybe -like 'otpauth://*') { return $maybe }
    }
    throw "No otpauth:// URI found in ZXing output."
}

# ---------- Wire up events ----------
$btnQR.Add_Click({
    try {
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Title = "Select QR image"
        $ofd.Filter = "Image Files|*.png;*.jpg;*.jpeg;*.gif;*.bmp|All Files|*.*"
        if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $path = $ofd.FileName

        $form.UseWaitCursor = $true; $form.Refresh()
        $uri = Invoke-DecodeQRViaZXing -ImagePath $path
        if ($uri) {
            $txtSecret.Text = $uri            # keep full URI
            Try-ApplyOtpUriParams $uri        # pre-fill algo/digits/period if present
            [System.Windows.Forms.MessageBox]::Show("QR decoded and secret applied.","QR Decoded",0)
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("QR decode failed: " + $_.Exception.Message, "Error", 0)
    } finally {
        $form.UseWaitCursor = $false
    }
})

$btnSample.Add_Click({
    # RFC vector: 20-byte secret (Base32)
    $txtSecret.Text = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    $cmbAlgo.SelectedItem = "SHA1"
    $numDigits.Value = 6
    $numPeriod.Value = 30
})

# Live generator + countdown
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({
    try {
        $secretText = $txtSecret.Text.Trim()
        if ($secretText -eq "") { $txtCurrent.Text = ""; $txtCountdown.Text = ""; return }

        $secretOnly = Get-SecretOnly $secretText
        $digits = [int]$numDigits.Value
        $period = [int]$numPeriod.Value
        $algo = [TotpHelper+HashAlgo]::SHA1
        switch ($cmbAlgo.SelectedItem) {
            "SHA256" { $algo = [TotpHelper+HashAlgo]::SHA256 }
            "SHA512" { $algo = [TotpHelper+HashAlgo]::SHA512 }
        }

        $nowUtc = [DateTime]::UtcNow
        $current = [TotpHelper]::Generate($secretOnly, $digits, $period, $algo, $nowUtc)
        $txtCurrent.Text = $current

        $epoch = [DateTime]::SpecifyKind((Get-Date "1970-01-01 00:00:00"), [System.DateTimeKind]::Utc)
        $unix = [int][Math]::Floor((($nowUtc - $epoch).TotalSeconds))
        $secsLeft = $period - ($unix % $period)
        $txtCountdown.Text = "$secsLeft s"
    } catch {
        $txtCurrent.Text = ""; $txtCountdown.Text = ""
    }
})
$timer.Start()

$btnValidate.Add_Click({
    $lblResult.Text = ""
    $secretText = $txtSecret.Text.Trim()
    if ($secretText -eq "") {
        $lblResult.Text = "Enter/paste a secret or otpauth URI."
        $lblResult.ForeColor = [System.Drawing.Color]::DarkRed
        return
    }

    $secretOnly = Get-SecretOnly $secretText
    $userCode = $txtToken.Text.Trim()
    if ($userCode -eq "") {
        $lblResult.Text = "Enter a token."
        $lblResult.ForeColor = [System.Drawing.Color]::DarkRed
        return
    }

    $digits = [int]$numDigits.Value
    $period = [int]$numPeriod.Value
    $algo = [TotpHelper+HashAlgo]::SHA1
    switch ($cmbAlgo.SelectedItem) {
        "SHA256" { $algo = [TotpHelper+HashAlgo]::SHA256 }
        "SHA512" { $algo = [TotpHelper+HashAlgo]::SHA512 }
    }
    $drift = [int]$numDrift.Value

    try {
        [string]$matched = $null
        [long]$matchedStep = 0
        $ok = [TotpHelper]::Validate($secretOnly, $userCode, $digits, $period, $algo, $drift, [DateTime]::UtcNow, [ref]$matched, [ref]$matchedStep)
        if ($ok) {
            $lblResult.Text = "VALID (matched step: $matchedStep)"
            $lblResult.ForeColor = [System.Drawing.Color]::DarkGreen
        } else {
            $lblResult.Text = "INVALID"
            $lblResult.ForeColor = [System.Drawing.Color]::DarkRed
        }
    } catch {
        $lblResult.Text = "Error: " + $_.Exception.Message
        $lblResult.ForeColor = [System.Drawing.Color]::DarkRed
    }
})

$form.Add_Shown({$form.Activate()})
[void]$form.ShowDialog()
