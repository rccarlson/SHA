module SHATests.ManualTests

open NUnit.Framework
open SecureHashingAlgorithms
open MessageDigestAlgorithms

let stringHash hash (input:string) (expectedResult:string)=
  let result =
    input.ToCharArray()
    |> Array.map byte
    |> hash
    |> UnitTests.bytesToByteString
  Assert.That(result.ToUpper(), Is.EqualTo(expectedResult.ToUpper()))

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

[<TestCase("", "31d6cfe0d16ae931b73c59d7e0c089c0")>]
[<TestCase("a", "bde52cb31de33e46245e05fbdbd6fb24")>]
[<TestCase("abc", "a448017aaf21d8525fc10ae87aa6729d")>]
[<TestCase("message digest", "d9130a8164549fe818874806e1c7014b")>]
[<TestCase("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9")>]
[<TestCase("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4")>]
[<TestCase("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536")>]
let MD4 (input : string) (expectedResult : string) = stringHash md4 input expectedResult

[<TestCase("", "d41d8cd98f00b204e9800998ecf8427e")>]
[<TestCase("This is a message sent by a computer user.", "922547e866c89b8f677312df0ccec8ee")>]
[<TestCase("Test value", "63e1ebd352652df46f8d00d8de6d177a")>]
[<TestCase("abc", "900150983cd24fb0d6963f7d28e17f72")>]
[<TestCase("Hello World!", "ED076287532E86365E841E92BFC50D8C")>]
[<TestCase("The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6")>]
[<TestCase("1", "c4ca4238a0b923820dcc509a6f75849b")>]
let MD5 (input : string) (expectedResult : string) = stringHash md5 input expectedResult

