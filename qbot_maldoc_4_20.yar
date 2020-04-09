rule qbot_maldoc_4_20 {
   meta:
      description = "Word Doc used in QBot April 2020 Campaign"
      author = "Jason Webb"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-04-06"
      hash1 = "d053510f598c2e02a9a27af9d498f58e0430ab4616987e67e77fa8d96f805bd7"
      hash2 = "65b2fcf91038ca52071d2ee439e297d395fb4707a9b7f0b48e75538ea1344dcb"
      hash3 = "f1c2e5bb9689823665b33ac487a507263db10265750782b2db5b7324ff51e376"
      hash4 = "d4dbc9b8b61d346d78890ad809284fdbbd4bcc8ae0b4b09a413e6617dce23557"
      hash5 = "067ec53789683d897b71d5b2a7a1a45c9600e7cc2746dfce5142d913a3e9069b"
      hash6 = "639c70c8e4075549dfc670dd25c3e6663d39a2411c0713a4d13498144e60ec60"
   strings:
      $s1 = "word/_rels/vbaProject.bin.relsPK" fullword ascii
      $s2 = "word/_rels/vbaProject.bin.relsl" fullword ascii
      $s3 = "word/vbaProject.bin" fullword ascii
      $s4 = "word/vbaProject.binPK" fullword ascii
      $s5 = "word/vbaData.xml" fullword ascii
      $s6 = "word/vbaData.xmlPK" fullword ascii
      $s7 = "word/media/image1.jpegPK" fullword ascii
      $s8 = "word/media/image1.jpeg" fullword ascii
      $s9 = "ACD Systems Digital Imaging" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 500KB and ( 9 of them )
      ) or ( all of them )
}
