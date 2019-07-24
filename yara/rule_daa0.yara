import "pe"

rule TheDao {
  strings:
    $b = { DA A0 }

  condition:
    uint16(0) == 0x5a4d and $b at pe.overlay.offset and pe.overlay.size > 100
}
