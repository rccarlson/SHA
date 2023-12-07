// These implementations are for personal education.
// Do not use this code in production environments.
// Secure Hash Standard: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

module SecureHashingAlgorithms

open System

let inline private addTuple_5<^T
  when ^T : (static member (+) : ^T * ^T -> ^T)>
  (a: ^T * ^T * ^T * ^T * ^T)
  (b: ^T * ^T * ^T * ^T * ^T) =
  let a0,a1,a2,a3,a4 = a
  let b0,b1,b2,b3,b4 = b
  a0 + b0, a1 + b1, a2 + b2, a3 + b3, a4 + b4

let inline private addTuple_8<^T
  when ^T : (static member (+) : ^T * ^T -> ^T)>
  (a: ^T * ^T * ^T * ^T * ^T * ^T * ^T * ^T)
  (b: ^T * ^T * ^T * ^T * ^T * ^T * ^T * ^T) =
  let a0,a1,a2,a3,a4,a5,a6,a7 = a
  let b0,b1,b2,b3,b4,b5,b6,b7 = b
  a0 + b0, a1 + b1, a2 + b2, a3 + b3,
  a4 + b4, a5 + b5, a6 + b6, a7 + b7
  
/// § 5.1.1
///
/// Pads the data with a 1, followed by zeros and the data length as a uint64 in big endian order.
let internal pad64 (data : byte array) =
  let ml = data.LongLength * 8L |> uint64
  let mlVals = uint64ToBytes_be ml
  pad mlVals data

/// § 5.1.2
///
/// Pads the data with a 1, followed by zeros and the data length as a uint128 in big endian order
let internal pad128 (data : byte array) =
  let length = data.LongLength |> uint64
  let mlVals =
    Array.append
      (uint64ToBytes_be (length >>> (64 - 3))) // upper
      (uint64ToBytes_be (length <<< 3)) // lower
  pad mlVals data

let inline private Ch<^T when ^T: (static member (&&&) : ^T * ^T -> ^T)
                          and ^T: (static member (~~~) : ^T -> ^T)
                          and ^T: (static member (^^^) : ^T * ^T -> ^T)>
                          (x:^T) (y:^T) (z:^T) =
                            (x &&& y) ^^^ ((~~~x) &&& z)

let inline private Parity<^T when ^T: (static member (^^^) : ^T * ^T -> ^T)>
                          (x:^T) (y:^T) (z:^T) =
                            x ^^^ y ^^^ z

let inline private Maj<^T when ^T: (static member (&&&) : ^T * ^T -> ^T)
                          and ^T: (static member (^^^) : ^T * ^T -> ^T)>
                          (x:^T) (y:^T) (z:^T) =
                            (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)

let inline private rotr<'T when 'T: (static member RotateRight : 'T * int -> 'T)>
  (value : 'T) (rotateAmount : int) =
    'T.RotateRight(value, rotateAmount)

let inline private rotl<'T when 'T: (static member RotateLeft : 'T * int -> 'T)>
  (value : 'T) (rotateAmount : int) =
    'T.RotateLeft(value, rotateAmount)

/// (4.4)
let inline private Σ256_0 x = (rotr x  2) ^^^ (rotr x 13) ^^^ (rotr x 22)
/// (4.5)
let inline private Σ256_1 x = (rotr x  6) ^^^ (rotr x 11) ^^^ (rotr x 25)
/// (4.6)
let inline private σ256_0 x = (rotr x  7) ^^^ (rotr x 18) ^^^ (x >>>  3)
/// (4.7)
let inline private σ256_1 x = (rotr x 17) ^^^ (rotr x 19) ^^^ (x >>> 10)

/// (4.10)
let inline private Σ512_0 x = (rotr x 28) ^^^ (rotr x 34) ^^^ (rotr x 39)
/// (4.11)
let inline private Σ512_1 x = (rotr x 14) ^^^ (rotr x 18) ^^^ (rotr x 41)
/// (4.12)
let inline private σ512_0 x = (rotr x  1) ^^^ (rotr x  8) ^^^ (x >>>  7)
/// (4.13)
let inline private σ512_1 x = (rotr x 19) ^^^ (rotr x 61) ^^^ (x >>>  6)

let inline private F t =
  if t < 20 then Ch else
  if t < 40 then Parity else
  if t < 60 then Maj else
  if t < 80 then Parity else
  raise (ArgumentOutOfRangeException($"t value of {t} is invalid"))

/// SHA-1 Constants
let inline private K_32 t =
  if t < 20 then 0x5a827999u else
  if t < 40 then 0x6ed9eba1u else
  if t < 60 then 0x8f1bbcdcu else
  if t < 80 then 0xca62c1d6u else
  raise (ArgumentOutOfRangeException($"t value of {t} is invalid"))

/// SHA-224 and SHA-256 Constants
///
/// These words represent the first thirty-two bits of the fractional
/// parts of the cube roots of the first sixty-four prime numbers
let inline private K_256 t =
  [|
    0x428a2f98u; 0x71374491u; 0xb5c0fbcfu; 0xe9b5dba5u; 0x3956c25bu; 0x59f111f1u; 0x923f82a4u; 0xab1c5ed5u;
    0xd807aa98u; 0x12835b01u; 0x243185beu; 0x550c7dc3u; 0x72be5d74u; 0x80deb1feu; 0x9bdc06a7u; 0xc19bf174u;
    0xe49b69c1u; 0xefbe4786u; 0x0fc19dc6u; 0x240ca1ccu; 0x2de92c6fu; 0x4a7484aau; 0x5cb0a9dcu; 0x76f988dau;
    0x983e5152u; 0xa831c66du; 0xb00327c8u; 0xbf597fc7u; 0xc6e00bf3u; 0xd5a79147u; 0x06ca6351u; 0x14292967u;
    0x27b70a85u; 0x2e1b2138u; 0x4d2c6dfcu; 0x53380d13u; 0x650a7354u; 0x766a0abbu; 0x81c2c92eu; 0x92722c85u;
    0xa2bfe8a1u; 0xa81a664bu; 0xc24b8b70u; 0xc76c51a3u; 0xd192e819u; 0xd6990624u; 0xf40e3585u; 0x106aa070u;
    0x19a4c116u; 0x1e376c08u; 0x2748774cu; 0x34b0bcb5u; 0x391c0cb3u; 0x4ed8aa4au; 0x5b9cca4fu; 0x682e6ff3u;
    0x748f82eeu; 0x78a5636fu; 0x84c87814u; 0x8cc70208u; 0x90befffau; 0xa4506cebu; 0xbef9a3f7u; 0xc67178f2u;
  |] |> Array.item t

/// SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Constants
///
/// These words represent the first sixty-four bits of the fractional
/// parts of the cube roots of the first eighty prime numbers.
let inline private K_512 t =
  [|
    0x428a2f98d728ae22uL; 0x7137449123ef65cduL; 0xb5c0fbcfec4d3b2fuL; 0xe9b5dba58189dbbcuL
    0x3956c25bf348b538uL; 0x59f111f1b605d019uL; 0x923f82a4af194f9buL; 0xab1c5ed5da6d8118uL
    0xd807aa98a3030242uL; 0x12835b0145706fbeuL; 0x243185be4ee4b28cuL; 0x550c7dc3d5ffb4e2uL
    0x72be5d74f27b896fuL; 0x80deb1fe3b1696b1uL; 0x9bdc06a725c71235uL; 0xc19bf174cf692694uL
    0xe49b69c19ef14ad2uL; 0xefbe4786384f25e3uL; 0x0fc19dc68b8cd5b5uL; 0x240ca1cc77ac9c65uL
    0x2de92c6f592b0275uL; 0x4a7484aa6ea6e483uL; 0x5cb0a9dcbd41fbd4uL; 0x76f988da831153b5uL
    0x983e5152ee66dfabuL; 0xa831c66d2db43210uL; 0xb00327c898fb213fuL; 0xbf597fc7beef0ee4uL
    0xc6e00bf33da88fc2uL; 0xd5a79147930aa725uL; 0x06ca6351e003826fuL; 0x142929670a0e6e70uL
    0x27b70a8546d22ffcuL; 0x2e1b21385c26c926uL; 0x4d2c6dfc5ac42aeduL; 0x53380d139d95b3dfuL
    0x650a73548baf63deuL; 0x766a0abb3c77b2a8uL; 0x81c2c92e47edaee6uL; 0x92722c851482353buL
    0xa2bfe8a14cf10364uL; 0xa81a664bbc423001uL; 0xc24b8b70d0f89791uL; 0xc76c51a30654be30uL
    0xd192e819d6ef5218uL; 0xd69906245565a910uL; 0xf40e35855771202auL; 0x106aa07032bbd1b8uL
    0x19a4c116b8d2d0c8uL; 0x1e376c085141ab53uL; 0x2748774cdf8eeb99uL; 0x34b0bcb5e19b48a8uL
    0x391c0cb3c5c95a63uL; 0x4ed8aa4ae3418acbuL; 0x5b9cca4f7763e373uL; 0x682e6ff3d6b2b8a3uL
    0x748f82ee5defb2fcuL; 0x78a5636f43172f60uL; 0x84c87814a1f0ab72uL; 0x8cc702081a6439ecuL
    0x90befffa23631e28uL; 0xa4506cebde82bde9uL; 0xbef9a3f7b2c67915uL; 0xc67178f2e372532buL
    0xca273eceea26619cuL; 0xd186b8c721c0c207uL; 0xeada7dd6cde0eb1euL; 0xf57d4f7fee6ed178uL
    0x06f067aa72176fbauL; 0x0a637dc5a2c898a6uL; 0x113f9804bef90daeuL; 0x1b710b35131c471buL
    0x28db77f523047d84uL; 0x32caab7b40c72493uL; 0x3c9ebe0a15c9bebcuL; 0x431d67c49c100d4cuL
    0x4cc5d4becb3e42b6uL; 0x597f299cfc657e2auL; 0x5fcb6fab3ad6faecuL; 0x6c44198c4a475817uL
  |] |> Array.item t

/// given a set of bytes, create an array of uint32 words
let internal buildMessageSchedule32 newSize generator (chunk : byte array) : uint32 array =
  Utility.buildArray newSize (fun W t ->
    if t < chunk.Length / 4 then 
      let byte0 = chunk[(t*4)+0]
      let byte1 = chunk[(t*4)+1]
      let byte2 = chunk[(t*4)+2]
      let byte3 = chunk[(t*4)+3]
      bytesToUint32 byte0 byte1 byte2 byte3
    else
      generator W t
  )
let internal buildMessageSchedule64 newSize generator (chunk : byte array) : uint64 array =
  Utility.buildArray newSize (fun W t ->
    if t < chunk.Length / 8 then 
      let byte0 = chunk[(t*8)+0]
      let byte1 = chunk[(t*8)+1]
      let byte2 = chunk[(t*8)+2]
      let byte3 = chunk[(t*8)+3]
      let byte4 = chunk[(t*8)+4]
      let byte5 = chunk[(t*8)+5]
      let byte6 = chunk[(t*8)+6]
      let byte7 = chunk[(t*8)+7]
      bytesToUint64 byte0 byte1 byte2 byte3 byte4 byte5 byte6 byte7
    else
      generator W t
  )

/// An object oriented implementation of the SHA1 hash function.
let sha1_oo (input : byte[]) : byte[] =
  // initialize variables
  let mutable h0 = 0x6745_2301u
  let mutable h1 = 0xEFCD_AB89u
  let mutable h2 = 0x98BA_DCFEu
  let mutable h3 = 0x1032_5476u
  let mutable h4 = 0xC3D2_E1F0u

  let blockSize = 64
  let dataChunks = input |> pad64 |> Array.chunkBySize blockSize

  for chunk in dataChunks do
    if (chunk.Length <> blockSize) then raise (ArgumentException($"Received block of size {chunk.Length}. All blocks must be of size {blockSize}"))
    // break chunk into sixteen 32-bit big-endian words w[i], 0<= i <= 15
    let words16 = Array.init 16 (fun i ->
      let byte0 = chunk[(i*4)+0]
      let byte1 = chunk[(i*4)+1]
      let byte2 = chunk[(i*4)+2]
      let byte3 = chunk[(i*4)+3]
      bytesToUint32 byte0 byte1 byte2 byte3
    )
    // extend the sixteen 32-bit words into eighty 32-bit words
    let words80 = Array.zeroCreate 80
    for i = 0 to 15 do words80[i] <- words16[i]
    for i = 16 to 79 do
      words80[i] <-
        (words80[i-3] ^^^ words80[i-8] ^^^ words80[i-14] ^^^ words80[i-16])
        |> fun value -> rotl value 1 // SHA-0 differs by not having this leftrotate.

    // initialize hash value for this chunk
    let mutable a,b,c,d,e = h0,h1,h2,h3,h4

    for t = 0 to 79 do
      let f = F t b c d
      let k = K_32 t

      let temp = (rotl a 5) + f + e + k + (uint words80[t])
      e <- d
      d <- c
      c <- rotl b 30
      b <- a
      a <- temp

    h0 <- h0 + a 
    h1 <- h1 + b 
    h2 <- h2 + c
    h3 <- h3 + d
    h4 <- h4 + e

  let hhBytes =
    [| h0; h1; h2; h3; h4 |]
    |> Array.collect (fun h -> Array.init 4 (fun i -> h <<< (8*i) >>> 24 |> byte))

  hhBytes

/// An implementation of the sha1 hash function, taking a functional design approach
let sha1 (input : byte[]) : byte[] =
  let rec sha1_internal t h (words: uint array) =
    if t = -1 then h else
    let a,b,c,d,e = sha1_internal (t-1) h words
    let f = F t b c d
    let k = K_32 t

    (rotl a 5) + f + e + k + (uint words[t]), // a
    a, // b
    (rotl b 30), // c
    c, // d
    d  // e

  let h_initial = 
    0x6745_2301u,
    0xEFCD_AB89u,
    0x98BA_DCFEu,
    0x1032_5476u,
    0xC3D2_E1F0u

  let h0,h1,h2,h3,h4 =
    input
    |> pad64
    |> Array.chunkBySize 64
    |> Array.map (buildMessageSchedule32 80 (fun W t ->
        W (t-3) ^^^ W (t-8) ^^^ W (t-14) ^^^ W (t-16)
        |> fun value -> rotl value 1
      )
    )
    |> Seq.fold
      (fun state chunk -> sha1_internal 79 state chunk |> addTuple_5 state)
      h_initial

  [|h0;h1;h2;h3;h4|]
  |> Array.collect (fun h -> Array.init 4 (fun i -> h <<< (8*i) >>> 24 |> byte))

let private sha256_h h_initial (input : byte[]) : byte[]=
  let rec sha256_internal t state (words : uint32 array) =
    if t = -1 then state else
    let a,b,c,d,e,f,g,h = sha256_internal (t-1) state words
    let T1 = h + Σ256_1 e + Ch e f g + K_256 t + words[t]
    let T2 = Σ256_0 a + Maj a b c

    T1 + T2, //a
    a, //b
    b, //c
    c, //d
    d + T1, // e
    e, //f
    f, //g
    g //h

  let h0,h1,h2,h3,h4,h5,h6,h7 =
    input
    |> pad64 // §5.1: padding the message
    |> Array.chunkBySize 64 // §5.2: parsing into message blocks
    |> Array.map (buildMessageSchedule32 64 (fun W t -> σ256_1 (W (t-2)) + W (t-7) + σ256_0 (W (t-15)) + W (t-16)))
    |> Seq.fold
      (fun state chunk -> sha256_internal 63 state chunk |> addTuple_8 state)
      h_initial

  [|h0;h1;h2;h3;h4;h5;h6;h7|]
  |> Array.collect (fun h -> Array.init 4 (fun i -> h <<< (8*i) >>> 24 |> byte))

let sha256 =
  let h_initial = // §5.3.3: H0
    0x6a09e667u,
    0xbb67ae85u,
    0x3c6ef372u,
    0xa54ff53au,
    0x510e527fu,
    0x9b05688cu,
    0x1f83d9abu,
    0x5be0cd19u

  sha256_h h_initial

let sha224 =
  // Same as sha256, with different h_init and outputting leftmost 224 bits (28 bytes)
  let h_initial = // § 5.3.2
    0xc1059ed8u,
    0x367cd507u,
    0x3070dd17u,
    0xf70e5939u,
    0xffc00b31u,
    0x68581511u,
    0x64f98fa7u,
    0xbefa4fa4u
  sha256_h h_initial >> Array.take 28

let private sha512_h h_initial (input: byte[]) : byte[] =
  let rec sha512_internal t state (words : uint64 array) =
    if t = -1 then state else
    let a,b,c,d,e,f,g,h = sha512_internal (t-1) state words
    let T1 = h + Σ512_1 e + Ch e f g + K_512 t + words[t]
    let T2 = Σ512_0 a + Maj a b c

    T1 + T2, //a
    a, //b
    b, //c
    c, //d
    d + T1, // e
    e, //f
    f, //g
    g //h

  let h0,h1,h2,h3,h4,h5,h6,h7 = 
    input
    |> pad128
    |> Array.chunkBySize 128
    |> Array.map (buildMessageSchedule64 80 (fun W t -> σ512_1 (W (t-2)) + W (t-7) + σ512_0 (W (t-15)) + W (t-16)))
    |> Seq.fold
      (fun state chunk -> sha512_internal 79 state chunk |> addTuple_8 state)
      h_initial

  [|h0;h1;h2;h3;h4;h5;h6;h7|]
  |> Array.collect (fun h -> Array.init 8 (fun i -> h <<< (8*i) >>> (64-8) |> byte))

let sha512 =
  let h_initial = // § 5.3.5: H0
    0x6a09e667f3bcc908uL,
    0xbb67ae8584caa73buL,
    0x3c6ef372fe94f82buL,
    0xa54ff53a5f1d36f1uL,
    0x510e527fade682d1uL,
    0x9b05688c2b3e6c1fuL,
    0x1f83d9abfb41bd6buL,
    0x5be0cd19137e2179uL
  sha512_h h_initial

let sha384 =
  // same as sha512, with different h_init and outputting leftmost 384 bits (48 bytes)
  let h_initial = // § 5.3.4: H0
    0xcbbb9d5dc1059ed8uL,
    0x629a292a367cd507uL,
    0x9159015a3070dd17uL,
    0x152fecd8f70e5939uL,
    0x67332667ffc00b31uL,
    0x8eb44a8768581511uL,
    0xdb0c2e0d64f98fa7uL,
    0x47b5481dbefa4fa4uL

  sha512_h h_initial >> Array.take 48

/// § 5.3.6 SHA-512/t
///
/// r a t-bit hash function based on SHA-512 whose output is truncated to t bits
let sha512t t =
  if t <= 0 || t > 512 || t = 384 then raise (ArgumentOutOfRangeException(t.ToString())) else
  let h0_primeprime =
    0x6a09e667f3bcc908uL ^^^ 0xa5a5a5a5a5a5a5a5uL,
    0xbb67ae8584caa73buL ^^^ 0xa5a5a5a5a5a5a5a5uL,
    0x3c6ef372fe94f82buL ^^^ 0xa5a5a5a5a5a5a5a5uL,
    0xa54ff53a5f1d36f1uL ^^^ 0xa5a5a5a5a5a5a5a5uL,
    0x510e527fade682d1uL ^^^ 0xa5a5a5a5a5a5a5a5uL,
    0x9b05688c2b3e6c1fuL ^^^ 0xa5a5a5a5a5a5a5a5uL,
    0x1f83d9abfb41bd6buL ^^^ 0xa5a5a5a5a5a5a5a5uL,
    0x5be0cd19137e2179uL ^^^ 0xa5a5a5a5a5a5a5a5uL
  let h0=
    let arr =
      $"SHA-512/{t}".ToCharArray()
      |> Array.map byte
      |> sha512_h h0_primeprime
      |> Array.chunkBySize 8
      |> Array.map (fun bytes -> bytesToUint64 bytes[0] bytes[1] bytes[2] bytes[3] bytes[4] bytes[5] bytes[6] bytes[7])
    arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7]

  sha512_h h0 >> Array.take (t/8)

let sha512_224 = sha512t 224
let sha512_256 = sha512t 256