rule ryuk_main_artifacts
{
 meta:
 description = "Rule for detecting the main Ryuk payload"
 author = "NCSC"
 strings:
 $ = ".RYK" wide
 $ = "RyukReadMe.html" wide
 $ = "UNIQUE_ID_DO_NOT_REMOVE" wide
 $ = "\\users\\Public\\finish" wide
 $ = "\\users\\Public\\sys" wide
 $ = "\\Documents and Settings\\Default User\\finish" wide
 $ = "\\Documents and Settings\\Default User\\sys" wide
 condition:
 uint16(0) == 0x5a4d and uint32(uint32(0x3c)) == 0x00004550 and all of
them
}
