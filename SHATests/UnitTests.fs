module SHATests.UnitTests

open NUnit.Framework

[<TestCase("00010203", ExpectedResult = [| 0y; 1y; 2y; 3y |])>]
[<TestCase("63faebb807f32be708cf00fc35519991dc4e7f68", ExpectedResult = [| 0x63y;0xfay;0xeby;0xb8y;0x07y;0xf3y;0x2by;0xe7y;0x08y;0xcfy;0x00y;0xfcy;0x35y;0x51y;0x99y;0x91y;0xdcy;0x4ey;0x7fy;0x68y |])>]
let byteStringToBytes str = RspReader.stringToByteArr str |> Array.map sbyte

let bytesToByteString (bytes:byte array) = bytes |> Array.map (fun byte -> byte.ToString("X02")) |> String.concat ""

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
[<TestCase("abc", [|
  "61626380"; "00000000"; "00000000"; "00000000"; "00000000"; "00000000"; "00000000"; "00000000";
  "00000000"; "00000000"; "00000000"; "00000000"; "00000000"; "00000000"; "00000000"; "00000018";
  |])>]
[<TestCase("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", [|
  "61626364"; "62636465"; "63646566"; "64656667"; "65666768"; "66676869"; "6768696A"; "68696A6B";
  "696A6B6C"; "6A6B6C6D"; "6B6C6D6E"; "6C6D6E6F"; "6D6E6F70"; "6E6F7071"; "80000000"; "00000000";
  "00000000"; "00000000"; "00000000"; "00000000"; "00000000"; "00000000"; "00000000"; "00000000";
  "00000000"; "00000000"; "00000000"; "00000000"; "00000000"; "00000000"; "00000000"; "000001C0";
  |])>]
let pad64 (input:string) (expected:string array) =
  let input = input.ToCharArray() |> Array.map byte
  let padResult = SecureHashingAlgorithms.pad64 input
  let expectedResult = String.concat "" expected |> RspReader.stringToByteArr
  Assert.That(expectedResult, Is.EqualTo(padResult))
  

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
[<TestCase("abc",
  [|
  "61626380";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";
  "00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";
  "00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";
  "00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000018";
  |])>]
[<TestCase("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
  [|
  "61626364";"65666768";"62636465";"66676869";"63646566";"6768696A";"64656667";"68696A6B";
  "65666768";"696A6B6C";"66676869";"6A6B6C6D";"6768696A";"6B6C6D6E";"68696A6B";"6C6D6E6F";
  "696A6B6C";"6D6E6F70";"6A6B6C6D";"6E6F7071";"6B6C6D6E";"6F707172";"6C6D6E6F";"70717273";
  "6D6E6F70";"71727374";"6E6F7071";"72737475";"80000000";"00000000";"00000000";"00000000";
  "00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";
  "00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";
  "00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";
  "00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000000";"00000380";
  |])>]
let pad128 (input:string) (expected:string array) =
  let input = input.ToCharArray() |> Array.map byte
  let padResult = SecureHashingAlgorithms.pad128 input
  let expectedResult = String.concat "" expected |> RspReader.stringToByteArr
  Assert.That(expectedResult, Is.EqualTo(padResult))

// FIPS 202 § 3.1.2

[<TestCase(64, 0,0,0, ExpectedResult = 0)>]   [<TestCase(64, 1,0,0, ExpectedResult = 64)>]   [<TestCase(64, 4,0,0, ExpectedResult = 256)>]
[<TestCase(64, 0,0,1, ExpectedResult = 1)>]   [<TestCase(64, 1,0,1, ExpectedResult = 65)>]   [<TestCase(64, 4,0,1, ExpectedResult = 257)>]
[<TestCase(64, 0,0,2, ExpectedResult = 2)>]   [<TestCase(64, 1,0,2, ExpectedResult = 66)>]   [<TestCase(64, 4,0,2, ExpectedResult = 258)>]
// ...
[<TestCase(64, 0,0,61, ExpectedResult = 61)>]   [<TestCase(64, 1,0,61, ExpectedResult = 125)>]   [<TestCase(64, 4,0,61, ExpectedResult = 317)>]
[<TestCase(64, 0,0,62, ExpectedResult = 62)>]   [<TestCase(64, 1,0,62, ExpectedResult = 126)>]   [<TestCase(64, 4,0,62, ExpectedResult = 318)>]
[<TestCase(64, 0,0,63, ExpectedResult = 63)>]   [<TestCase(64, 1,0,63, ExpectedResult = 127)>]   [<TestCase(64, 4,0,63, ExpectedResult = 319)>]

[<TestCase(64, 0,1,0, ExpectedResult = 320)>]   [<TestCase(64, 1,1,0, ExpectedResult = 384)>]   [<TestCase(64, 4,1,0, ExpectedResult = 576)>]
[<TestCase(64, 0,1,1, ExpectedResult = 321)>]   [<TestCase(64, 1,1,1, ExpectedResult = 385)>]   [<TestCase(64, 4,1,1, ExpectedResult = 577)>]
[<TestCase(64, 0,1,2, ExpectedResult = 322)>]   [<TestCase(64, 1,1,2, ExpectedResult = 386)>]   [<TestCase(64, 4,1,2, ExpectedResult = 578)>]
// ...
[<TestCase(64, 0,1,61, ExpectedResult = 381)>]   [<TestCase(64, 1,1,61, ExpectedResult = 445)>]   [<TestCase(64, 4,1,61, ExpectedResult = 637)>]
[<TestCase(64, 0,1,62, ExpectedResult = 382)>]   [<TestCase(64, 1,1,62, ExpectedResult = 446)>]   [<TestCase(64, 4,1,62, ExpectedResult = 638)>]
[<TestCase(64, 0,1,63, ExpectedResult = 383)>]   [<TestCase(64, 1,1,63, ExpectedResult = 447)>]   [<TestCase(64, 4,1,63, ExpectedResult = 639)>]

[<TestCase(64, 0,2,0, ExpectedResult = 640)>]   [<TestCase(64, 1,2,0, ExpectedResult = 704)>]   [<TestCase(64, 4,2,0, ExpectedResult = 896)>]
[<TestCase(64, 0,2,1, ExpectedResult = 641)>]   [<TestCase(64, 1,2,1, ExpectedResult = 705)>]   [<TestCase(64, 4,2,1, ExpectedResult = 897)>]
[<TestCase(64, 0,2,2, ExpectedResult = 642)>]   [<TestCase(64, 1,2,2, ExpectedResult = 706)>]   [<TestCase(64, 4,2,2, ExpectedResult = 898)>]
// ...
[<TestCase(64, 0,2,61, ExpectedResult = 701)>]   [<TestCase(64, 1,2,61, ExpectedResult = 765)>]   [<TestCase(64, 4,2,61, ExpectedResult = 957)>]
[<TestCase(64, 0,2,62, ExpectedResult = 702)>]   [<TestCase(64, 1,2,62, ExpectedResult = 766)>]   [<TestCase(64, 4,2,62, ExpectedResult = 958)>]
[<TestCase(64, 0,2,63, ExpectedResult = 703)>]   [<TestCase(64, 1,2,63, ExpectedResult = 767)>]   [<TestCase(64, 4,2,63, ExpectedResult = 959)>]

let stateArray w x y z =
  w * (5*y + x) + z