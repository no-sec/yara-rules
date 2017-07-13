import "hash"
import "pe"

rule jaff_binary {
  meta:
    author = "Jan Starke"
    date = "2017-06-12"
    score = 100
  condition:
    ( hash.md5(0, filesize) == "c9c897215e6f805eaf03ad56afd6e331" )
      or
    ( pe.version_info["LegalCopyright"] == "Outerspace Software Copyright \xa9. All rights reserved." and
      pe.version_info["InternalName"] == "Approximately10gbps" and
      pe.version_info["CompanyName"] == "Outerspace Software" )
}

rule jaff_documentation {
  meta:
    author = "Jan Starke"
    date = "2017-06-12"
    score = 10

  strings:
    $docu_title = "JAFF DECRYPTOR"
    $docu_url = /http:.{100}\.onion/
    $docu_text = "To decrypt flies you need to obtain the private key."
  condition:
    $docu_title or $docu_url or $docu_text
}
