// Packer / obfuscation signatures.

rule Ariados_UPXPacked {
    meta:
        severity = "medium"
        description = "UPX packer signature present"
    strings:
        $u1 = "UPX!"
        $u2 = "UPX0"
        $u3 = "UPX1"
    condition:
        2 of them
}
