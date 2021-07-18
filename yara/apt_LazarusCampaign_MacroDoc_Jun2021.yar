rule LazarusCampaign_MacroDoc_Jun2021 : WindowsMalware {

   meta:

      author = "AlienLabs"

      description = "Detects Lazarus campaign macro document Jun2021."

      reference = "https://otx.alienvault.com/pulse/294acafed42c6a4f546486636b4859c074e53d74be049df99932804be048f42c"

      SHA256 = "294acafed42c6a4f546486636b4859c074e53d74be049df99932804be048f42c"


   strings:


      $a1 = "ZSBydW4gaW4gRE9TIG1vZGUuDQ0KJA" ascii //run in DOS mode. - base64 encoded

      $a2 = "c:\\Drivers"

      $a3 = "AAAAAAAAAA=" ascii // base64 content

      $a4 = "CreateObject(\"Scripting.FileSystemObject\").CreateTextFile"

      $a5 = "cmd /c copy"

      $a6 = {73 79 73 74 65 6d 33 32 5c 2a 65 72 74 75 74 2a 2e 65 78 65} // system32\*ertut*.exe

      $a7 = {25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 65 78 70 2a 2e 65 78 65} // %systemroot%\exp*.exe

      $a8 = "sleep 1000"

      $a9 = "cmd /c explorer.exe /root"

      $a10 = "-decode "

      $b = "tAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5v" ascii //This program cannot - base64 encoded



    condition:

      uint16(0) == 0xCFD0 and

        filesize < 2000KB and

        $b and

        5 of ($a*)

}
