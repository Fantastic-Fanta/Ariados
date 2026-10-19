// Illustrative macOS indicator rules. Point ariados at a directory of real
// community rules with `--yara <dir>` for broad coverage.

rule Ariados_FakePasswordPrompt {
    meta:
        severity = "high"
        description = "AppleScript dialog that asks the user for their password"
    strings:
        $dlg = "display dialog" nocase
        $hidden = "with hidden answer" nocase
    condition:
        all of them
}

rule Ariados_BrowserCredentialPaths {
    meta:
        severity = "medium"
        description = "References browser credential stores (Login Data / keychain)"
    strings:
        $a = "Google/Chrome/Default/Login Data"
        $b = "login.keychain-db"
        $c = "cookies.sqlite"
    condition:
        2 of them
}

rule Ariados_CurlPipeShell {
    meta:
        severity = "high"
        description = "Downloads a script and pipes it directly to a shell"
    strings:
        $a = /curl\s+[^\n]{0,120}\|\s*(sh|bash|zsh)/
    condition:
        $a
}
