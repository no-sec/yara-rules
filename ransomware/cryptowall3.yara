import "hash"
import "pe"

rule cryptowall3_binary {
  meta:
    author = "Jan Starke"
    date = "2017-07-13"
    score = 100
  condition:
    ( hash.md5(0, filesize) == "c43a9adc745077ddbfd2769ae4e37a2d" )
      or
    ( hash.md5(0, filesize) == "e5710c77157f87b5ba18eb8dbe9a9547" )
      or
    ( hash.md5(0, filesize) == "2252db96eabc4ba2b3b48d636818a97a" )
      or
    ( hash.md5(0, filesize) == "45347fe0e3704151b952302e6c77a889" )
}
