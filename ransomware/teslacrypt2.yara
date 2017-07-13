import "hash"
import "pe"

rule teslacrypt2_binary {
  meta:
    author = "Jan Starke"
    date = "2017-07-13"
    score = 100
  condition:
    ( hash.md5(0, filesize) == "a31e6ec2c7394425ee8a666af7cbc018" )
}
