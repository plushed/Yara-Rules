rule vbs_sins_many_small_arrays {
  meta:
    description = "Isolates 'interesting' vbs files that obfuscate using thousands of small arrays of nonsense. As seen with Qakbot"
    date = "2019-10-03"
    author = "Ryan C. Moon (@moonbas3)"
    samples = "637b148a482a96cad07aafec5c9726cf, bc24d1771a323d2ef64aa13ba0c1f29c, 26446c8003ec839ddb9e35bf4a51b154"
    tlp = "green"
    prod = "true"
  strings:
    $s1 = /=array\(([a-z0-9]{2,12},){25}/ nocase
  condition:
    filesize > 100KB and filesize < 10000KB and
    // exclude exe, zip, msi, rar
    uint16(0) != 0x5a4d and uint16(0) != 0x4b50 and
    uint16(0) != 0x534d and uint16(0) != 0x6152 and
    $s1 and #s1 > 1000
}
