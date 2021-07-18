rule LazarusCampaign_Payload_Jun2021 : WindowsMalware {

   meta:

      author = "AlienLabs"

      description = "Detects Lazarus campaign downloader Jun2021."

      reference = "https://otx.alienvault.com/pulse/294acafed42c6a4f546486636b4859c074e53d74be049df99932804be048f42c"

      SHA256 = "f5563f0e63d9deed90b683a15ebd2a1fda6b72987742afb40a1202ddb9e867d0"


   strings:


      $a1 = "Office ClickToRun" wide ascii

      $a2 = "C:\\Drivers\\"


    condition:


      uint16(0) == 0x5A4D and all of them

}
