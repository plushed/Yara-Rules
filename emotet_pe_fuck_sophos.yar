/*
    Template YARA ruleset
*/
rule Emotet_PE_Sophos {
   meta:
      author = "Jason Webb"
      description = "This was used in early 2020 Emotet campaigns where the PE file conveniently had the string, Fuck Sophos, in the content"
      date = "2020-02-06"
      hash1 = "a04a5daab208c4971a9d199342d10cdc693e4293a3db10b7b75e00fa8ed64a21"
   strings:
      $f0 = "Fuck Sophos" fullword wide
   condition:
 uint16(0) == 0x5a4d and
 filesize < 800KB and all of them
 }
