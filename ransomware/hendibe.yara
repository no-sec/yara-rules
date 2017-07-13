import "hash"
import "pe"

rule hendibe_binary {
  meta:
    author = "Jan Starke"
    date = "2017-07-13"
    score = 100
  condition:
    ( hash.md5(0, filesize) == "5acb59a0974c2a19992be4a2d2c630ad" )
}
