
rule TwinPeaks
{
  strings:
    $cooper = "Cooper"
    $pattern = { e9 ea eb ec ed ee ef f0}

  condition:
    uint16(0) == 0x5a4d and $cooper and ($pattern in (@cooper[1]..@cooper[1]+100))
}
