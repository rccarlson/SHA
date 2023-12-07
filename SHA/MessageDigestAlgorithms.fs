module MessageDigestAlgorithms

open System

/// 1-indexed table of values derived from sine
let private T = Array.init 65 (fun i -> (2.0**32) * abs(sin(float i)) |> uint32)

/// follows padding rules, while appending data in little endian
let internal pad64_le (data : byte array) =
  let ml = data.LongLength * 8L |> uint64
  let mlVals = uint64ToBytes_le ml
  pad mlVals data

// https://datatracker.ietf.org/doc/html/rfc1186
let md4 (input : byte array) : byte array =
  let F x y z = (x &&& y) ||| (~~~x &&& z)            // XY v not(X)Z
  let G x y z = (x &&& y) ||| (x &&& z) ||| (y &&& z) // XY v XZ v YZ
  let H x y z = x ^^^ y ^^^ z                         // X xor Y xor Z

  let h0,h1,h2,h3 =
    input
    |> pad64_le
    |> byteArrToUint32_le
    |> Seq.chunkBySize 16
    |> Seq.fold (fun (aa,bb,cc,dd) X ->
        let mutable a,b,c,d = aa,bb,cc,dd

        let op f a b c d i s k =
          // In the spec, the <<< operator denotes a left rotation. In F#, the <<< operator denotes a left shift.
          // In this section, the <<< operator is redefined to read the same as the spec.

          /// Rotate left
          let (<<<) value rotateAmount = UInt32.RotateLeft(value, rotateAmount)
          // a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
          (a + (f b c d) + X[i] + k) <<< s

        let abcd f i s k = a <- op f a b c d i s k
        let dabc f i s k = d <- op f d a b c i s k
        let cdab f i s k = c <- op f c d a b i s k
        let bcda f i s k = b <- op f b c d a i s k

        // round 1
        let k = 0x0u
        abcd F  0  3 k; dabc F  1  7 k; cdab F  2 11 k; bcda F  3 19 k
        abcd F  4  3 k; dabc F  5  7 k; cdab F  6 11 k; bcda F  7 19 k
        abcd F  8  3 k; dabc F  9  7 k; cdab F 10 11 k; bcda F 11 19 k
        abcd F 12  3 k; dabc F 13  7 k; cdab F 14 11 k; bcda F 15 19 k
        // round 2
        let k = 0x5A827999u
        abcd G  0  3 k; dabc G  4  5 k; cdab G  8  9 k; bcda G 12 13 k
        abcd G  1  3 k; dabc G  5  5 k; cdab G  9  9 k; bcda G 13 13 k
        abcd G  2  3 k; dabc G  6  5 k; cdab G 10  9 k; bcda G 14 13 k
        abcd G  3  3 k; dabc G  7  5 k; cdab G 11  9 k; bcda G 15 13 k
        // round 3
        let k = 0x6ED9EBA1u
        abcd H  0  3 k; dabc H   8 9 k; cdab H  4 11 k; bcda H 12 15 k
        abcd H  2  3 k; dabc H  10 9 k; cdab H  6 11 k; bcda H 14 15 k
        abcd H  1  3 k; dabc H   9 9 k; cdab H  5 11 k; bcda H 13 15 k
        abcd H  3  3 k; dabc H  11 9 k; cdab H  7 11 k; bcda H 15 15 k

        (a + aa, b + bb, c + cc, d + dd)
      )
      ( // initial buffer
        0x67_45_23_01u,
        0xef_cd_ab_89u,
        0x98_ba_dc_feu,
        0x10_32_54_76u
      )
  [|h0;h1;h2;h3|]
  |> Array.collect (int32ToBytes >> Array.rev)

// https://datatracker.ietf.org/doc/html/rfc1321
let md5 (input : byte array) : byte array =
  let F x y z = (x &&& y) ||| (~~~x &&& z) // XY v not(X) Z
  let G x y z = (x &&& z) ||| (y &&& ~~~z) // XZ v Y not(Z)
  let H x y z = x ^^^ y ^^^ z              // X xor Y xor Z
  let I x y z = y ^^^ (x ||| ~~~z)         // Y xor (X v not(Z))

  let h0,h1,h2,h3 =
    input
    |> pad64_le
    |> byteArrToUint32_le
    |> Seq.chunkBySize 16
    |> Seq.fold (fun (aa,bb,cc,dd) X ->
        let mutable a,b,c,d = aa,bb,cc,dd

        let op f  a b c d  k s i =
          // In the spec, the <<< operator denotes a left rotation. In F#, the <<< operator denotes a left shift.
          // In this section, the <<< operator is redefined to read the same as the spec.

          /// Rotate left
          let inline (<<<) value rotateAmount = UInt32.RotateLeft(value, rotateAmount)
          // a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
          b + ((a + (f b c d) + (X[k]) + T[i]) <<< s)

        let abcd f k s i = a <- op f a b c d k s i
        let dabc f k s i = d <- op f d a b c k s i
        let cdab f k s i = c <- op f c d a b k s i
        let bcda f k s i = b <- op f b c d a k s i

        // round 1
        abcd F  0  7  1; dabc F  1 12  2; cdab F  2 17  3; bcda F  3 22  4
        abcd F  4  7  5; dabc F  5 12  6; cdab F  6 17  7; bcda F  7 22  8
        abcd F  8  7  9; dabc F  9 12 10; cdab F 10 17 11; bcda F 11 22 12
        abcd F 12  7 13; dabc F 13 12 14; cdab F 14 17 15; bcda F 15 22 16
        // round 2
        abcd G  1  5 17; dabc G  6  9 18; cdab G 11 14 19; bcda G  0 20 20
        abcd G  5  5 21; dabc G 10  9 22; cdab G 15 14 23; bcda G  4 20 24
        abcd G  9  5 25; dabc G 14  9 26; cdab G  3 14 27; bcda G  8 20 28
        abcd G 13  5 29; dabc G  2  9 30; cdab G  7 14 31; bcda G 12 20 32
        // round 3
        abcd H  5  4 33; dabc H  8 11 34; cdab H 11 16 35; bcda H 14 23 36
        abcd H  1  4 37; dabc H  4 11 38; cdab H  7 16 39; bcda H 10 23 40
        abcd H 13  4 41; dabc H  0 11 42; cdab H  3 16 43; bcda H  6 23 44
        abcd H  9  4 45; dabc H 12 11 46; cdab H 15 16 47; bcda H  2 23 48
        // round 4
        abcd I  0  6 49; dabc I  7 10 50; cdab I 14 15 51; bcda I  5 21 52
        abcd I 12  6 53; dabc I  3 10 54; cdab I 10 15 55; bcda I  1 21 56
        abcd I  8  6 57; dabc I 15 10 58; cdab I  6 15 59; bcda I 13 21 60
        abcd I  4  6 61; dabc I 11 10 62; cdab I  2 15 63; bcda I  9 21 64

        (a + aa, b + bb, c + cc, d + dd)
      )
      ( // initial buffer
        0x67_45_23_01u,
        0xef_cd_ab_89u,
        0x98_ba_dc_feu,
        0x10_32_54_76u
      )

  [|h0;h1;h2;h3|]
  |> Array.collect (int32ToBytes >> Array.rev)