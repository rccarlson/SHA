// Tests based on the test vectors found at https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing

module SHATests.RSPTests

open SHATests.RspReader
open NUnit.Framework
open SecureHashingAlgorithms

let getRspCases (baseFileName:string) =
  let shorts = readRspFromFile $@"RSP Files\{baseFileName}ShortMsg.rsp"
  let longs  = readRspFromFile $@"RSP Files\{baseFileName}LongMsg.rsp"
  Seq.append shorts longs
  
let Sha1RspSource = getRspCases "SHA1"
[<TestCaseSource(nameof(Sha1RspSource))>]
let ``SHA1 Message`` (test : RspEntry) = Assert.That(test.MD, Is.EqualTo(test.Msg |> sha1))
  
let Sha224RspSource = getRspCases "SHA224"
[<TestCaseSource(nameof(Sha224RspSource))>]
let ``SHA224 Message`` (test : RspEntry) = Assert.That(test.MD, Is.EqualTo(test.Msg |> sha224))
  
let Sha256RspSource = getRspCases "SHA256"
[<TestCaseSource(nameof(Sha256RspSource))>]
let ``SHA256 Message`` (test : RspEntry) = Assert.That(test.MD, Is.EqualTo(test.Msg |> sha256))
  
let Sha384RspSource = getRspCases "SHA384"
[<TestCaseSource(nameof(Sha384RspSource))>]
let ``SHA384 Message`` (test : RspEntry) = Assert.That(test.MD, Is.EqualTo(test.Msg |> sha384))

let Sha512RspSource = getRspCases "SHA512"
[<TestCaseSource(nameof(Sha512RspSource))>]
let ``SHA512 Message`` (test : RspEntry) = Assert.That(test.MD, Is.EqualTo(test.Msg |> sha512))

let Sha512_224RspSource = getRspCases "SHA512_224"
[<TestCaseSource(nameof(Sha512_224RspSource))>]
let ``SHA512_224 Message`` (test : RspEntry) = Assert.That(test.MD, Is.EqualTo(test.Msg |> sha512_224))

let Sha512_256RspSource = getRspCases "SHA512_256"
[<TestCaseSource(nameof(Sha512_256RspSource))>]
let ``SHA512_256 Message`` (test : RspEntry) = Assert.That(test.MD, Is.EqualTo(test.Msg |> sha512_256))