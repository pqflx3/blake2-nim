import bit

proc rotr*[T = SomeUnsignedInt](value: T; amount: SomeInteger): T =
  ## Rotate right the bits of 'value' of type 'T' by 'amount'
  let bits = (sizeof(T) * BitsInByte)
  let amount = amount and (bits - 1)
  result = (value shr amount) xor (value shl ( bits - amount))
  
template rotl*(x, y: typed): untyped =
  ## Rotate left bytes
  rotr(x, (sizeof(x) * BitsInByte) - y)
  
proc get64*(a: openarray[byte]): uint64 =
  # Little Endian access a uint64 from a sequence of bytes

  doAssert a.len >= 7

  result = result xor
    (uint64(a[0]) shl 0) xor
    (uint64(a[1]) shl 8) xor
    (uint64(a[2]) shl 16) xor
    (uint64(a[3]) shl 24) xor
    (uint64(a[4]) shl 32) xor
    (uint64(a[5]) shl 40) xor
    (uint64(a[6]) shl 48) xor
    (uint64(a[7]) shl 56)

when isMainModule:
  let x: uint64 = 18
  doAssert rotl(x, 129) == 36
  doAssert rotr(x, -65) == 36
  doAssert rotr(x, 63) == 36