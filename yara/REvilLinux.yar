rule REvilLinux

{

    meta:

        author = "AlienLabs"

        description = "REvil Linux"

        sha256 = "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4  "

    strings:

        $func = "File [%s] was NOT encrypted"

        $sleep = "esxcli"

        $re = "[%s] is protected by os"

        $a3 = "Error create note in dir %s"

    condition:

        uint32(0) == 0x464C457F and 3 of them

}
