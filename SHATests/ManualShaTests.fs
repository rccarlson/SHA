module SHATests.ManualShaTests

open NUnit.Framework
open SecureHashingAlgorithms

let stringHash hash (input:string) (expectedResult:string)=
  let result =
    input.ToCharArray()
    |> Array.map byte
    |> hash
    |> UnitTests.bytesToByteString
  Assert.That(expectedResult.ToUpper(), Is.EqualTo(result.ToUpper()))

[<TestCase("abc",
  "A9993E364706816ABA3E25717850C26C9CD0D89D")>]
[<TestCase("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  "84983E441C3BD26EBAAE4AA1F95129E5E54670F1")>]
[<TestCase("dd4df644eaf3d85bace2b21accaa22b28821f5cddd4df644eaf3d85bace2b21accaa22b28821f5cddd4df644eaf3d85bace2b21accaa22b28821f5cd",
  "7cfd661343760506cf066b8c7518f118bcb1d5a5")>]
let SHA1 (input : string) (expectedResult : string)= stringHash sha1 input expectedResult

[<TestCase("abc",
  "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")>]
[<TestCase("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1")>]
let SHA256 (input : string) (expectedResult : string)= stringHash sha256 input expectedResult

[<TestCase("abc",
  "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F")>]
[<TestCase("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
  "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909")>]
let SHA512 (input : string) (expectedResult : string)= stringHash sha512 input expectedResult