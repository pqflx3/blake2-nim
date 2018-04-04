import strutils
import sequtils
import streams
import bits / ops

type
  Blake2bCtx = object
    b: array[128, byte] # input buffer
    h: array[8, uint64] # chained state
    t: array[2, uint64] # total number of bytes
    c: uint64           # pointer for b[]
    outlen: uint64      # digest size

const
  blake2b_iv: array[8, uint64] = mapLiterals( [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179], uint64)

  sigma: array[12, array[16, byte]] = mapLiterals( [
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ] ,
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ] ,
    [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ] ,
    [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ] ,
    [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ] ,
    [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ] ,
    [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ] ,
    [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ] ,
    [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ] ,
    [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 ] ,
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ] ,
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ] ], byte)

proc `$`(p: pointer): string =
  result = $cast[int64](p)

proc print(arr: openarray[uint64]) =
  stdOut.write("[")
  for i in 0..arr.high:
    stdOUt.write arr[i].toHex 
    stdOut.write ","
    if (i mod 3) == 2:
      stdOut.write "\n"
  stdOut.write "]\n"


proc b2b_get64(p : uint64): uint64 =
  ## little endian byte access
  result = p  

template mix(v,a,b,c,d,x,y : untyped) =
  v[a] = v[a] + v[b] + x
  v[d] = rotr(v[d] xor v[a], 32)
  v[c] = v[c] + v[d]
  v[b] = rotr(v[b] xor v[c], 24)
  v[a] = v[a] + v[b] + y
  v[d] = rotr(v[d] xor v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = rotr(v[b] xor v[c], 63)

proc blake2b_compress(ctx: var Blake2bCtx; last: bool) =
  var v: array[16, uint64]
  var m: array[16, uint64]

  for i in 0..<8:
    v[i] = ctx.h[i]
    v[i+8] = blake2b_iv[i]
  
  v[12] = v[12] xor ctx.t[0]
  v[13] = v[13] xor ctx.t[1]

  if(last):
    v[14] = not v[14]

  for i in 0..<16:
    m[i] = get64(ctx.b.toOpenArray(8*i, 8*(i+1) - 1))
    # m[i] = cast[ptr uint64](addr ctx.b[8*i])[]
    # m[i] = b2b_get64(ctx.b[8*i])

  echo "m: "
  print m
  echo "v: "
  print v

  for i in 0..<12:  # twelve rounds
    mix(v, 0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]])
    mix(v, 1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]])
    mix(v, 2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]])
    mix(v, 3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]])
    mix(v, 0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]])
    mix(v, 1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]])
    mix(v, 2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]])
    mix(v, 3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]])

    echo "i: ", i
    print v
  
  for i in 0..<8:
    ctx.h[i] = ctx.h[i] xor v[i] xor v[i+8]

# proc blake2b_update*(ctx: var Blake2bCtx, data: var cstring; inlen: int) =
#   ## Adds 'inlen' bytes from 'in' into the hash
#   for i in 0..<inlen:
#     if ctx.c == 128:
#       ctx.t[0] += ctx.c
#       if ctx.t[0] < ctx.c:
#         ctx.t[1] += 1
#       blake2b_compress(ctx, false)
#       ctx.c = 0
#     ctx.b[ctx.c] = (addr data)[i.int].uint8
#     ctx.c += 1

proc blake2b_update*(ctx: var Blake2bCtx, data: openArray[byte]) =
  ## Adds 'inlen' bytes from 'in' into the hash
  for i in 0..< data.len:
    if ctx.c == 128:
      ctx.t[0] += ctx.c
      if ctx.t[0] < ctx.c:
        ctx.t[1] += 1
      blake2b_compress(ctx, false)
      ctx.c = 0
    ctx.b[ctx.c] = data[i]
    ctx.c += 1    

# proc blake2b_init*(ctx: var Blake2bCtx, outlen: uint64, key: var cstring; keylen: int): int64 =
proc blake2b_init*(ctx: var Blake2bCtx, outlen: uint64, key: openArray[byte]): int64 =
  ## Initialize Black2bCtx with an optional key
  ## 1 <= outlen <=  64 - digest size (in bytes)
  ## Secret key is optional, default keylen = 0, keylen <= 64
  doAssert( 1'u64 <= outlen and outlen <= 64'u64 )
  doAssert( len(key) <= 64)

  for i in 0..<8:
    ctx.h[i] = blake2b_iv[i]
  ctx.h[0] = ctx.h[0] xor 0x01010000'u64 xor (len(key).uint64 shl 8) xor outlen;

  ctx.t[0] = 0
  ctx.t[1] = 0
  ctx.c = 0
  ctx.outlen = outlen

  for i in len(key)..<128:
    ctx.b[i] = 0
  if len(key) > 0:
    blake2b_update(ctx, key)
    ctx.c = 128

  result = 0

proc blake2b_final*(ctx: var Blake2bCtx): string =
  ctx.t[0] += ctx.c
  if(ctx.t[0] > ctx.c):
    ctx.t[1] += 1

  while ctx.c < 128:
    ctx.b[ctx.c] = 0
    ctx.c += 1
  blake2b_compress(ctx, true)

  result = ""

  for i in 0..ctx.outlen-1:
    var c = (ctx.h[i shr 3] shr (8'u64 * (i and 7))) and 0xFF
    result.add cast[char](c)

proc blake2b(input: openArray[byte]): string =
  var ctx: Blake2bCtx
  var key: seq[byte] = @[]
  let outlen = 64'u64

  if blake2b_init(ctx, outlen, key) != 0:
    doAssert(false)
  blake2b_update(ctx, input)

  let res = blake2b_final(ctx)
  var res2: string = ""
  for c in res:
    res2.add c.toHex
  return res2

# proc blake2b*(s: var cstring): string =
#   var ctx: Blake2bCtx
#   var key: cstring = ""

#   if blake2b_init(ctx, 64'u64, key, len(key)) != 0:
#     doAssert(1 == 0)
#   blake2b_update(ctx, s, len(s))

#   let res = blake2b_final(ctx)
#   var res2: string = ""
#   for c in res:
#     res2.add c.toHex
#   return res2

proc blake2b_file(filename: string): string =
    var ctx: Blake2bCtx
    var key: seq[byte] = @[]
    let out_len = 64'u64
  
    if blake2b_init(ctx, out_len, key) != 0:
      doAssert(1 == 0)
     

    let f = open(filename, fmRead)
    var buffer: array[4096, byte]
    while not f.endOfFile:
        let bytes_read = f.readBytes(buffer, 0, 4096)
        if bytes_read != 4096:
          blake2b_update(ctx, buffer.toOpenArray(0, bytes_read - 1))
          break
        blake2b_update(ctx, buffer)
  
    let res = blake2b_final(ctx)
    var res2: string = ""
    for c in res:
      res2.add c.toHex
    return res2

proc conv(s: string): seq[byte] =
  result = @[]
  for c in s:
    result.add c.byte

when isMainModule:
  echo "Test Black2b"  
#   var s: cstring = "abc"
#   echo blake2b(s)

#   var tmp: cstring = """abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789abcdefg0123456789"""
#   echo "hash1:", blake2b(tmp)

  let tmp = "abc"
  let inp = conv(tmp)
  echo "abc hash: ", blake2b(inp)

  # echo "file hash: ", blake2b_file("tmp")

#   let filename = "C:/Users/Marco/Downloads/manjaro-kde-17.1.2-stable-x86_64.iso"
#   echo "hash:", blake2b_file(filename)
