import "hash"
import "pe"

rule downloader_ahz {
  meta:
    author = "Jan Starke"
    date = "2017-07-13"
    score = 100
  condition:
    ( hash.md5(0, filesize) == "ceb9635a093980b5cfa762552834172b" )
}

rule downloader_agb {
  meta:
    author = "Jan Starke"
    date = "2017-07-13"
    score = 100
  condition:
    ( hash.md5(0, filesize) == "e22e7d9851b9c8e92a8cab4dba71ec8d" )
}
