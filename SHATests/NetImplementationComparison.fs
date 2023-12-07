module SHATests.NetImplementationComparison

open NUnit.Framework
open SecureHashingAlgorithms
open MessageDigestAlgorithms

let rand = System.Random(0)

let getRandomBytes length =
  let maxValue = System.Byte.MaxValue |> int
  Array.init length (fun _ -> rand.Next(maxValue + 1) |> byte)

/// Tests random byte-wise inputs to assure the two provided implementations are equivalent
let assertImplementationsEqual referenceImplementation testImplementation numTests =
  for i = 1 to numTests do
    let testBytes = getRandomBytes i
    let referenceResult : byte array = referenceImplementation testBytes
    let testResult : byte array = testImplementation testBytes
    Assert.That(testResult, Is.EqualTo(referenceResult))

[<Test>]
let MD5() =
  use netImplementation = System.Security.Cryptography.MD5.Create()
  assertImplementationsEqual netImplementation.ComputeHash md5 1_000

[<Test>]
let SHA1 () =
  use netImplementation = System.Security.Cryptography.SHA1.Create()
  assertImplementationsEqual netImplementation.ComputeHash sha1 1_000

[<Test>]
let SHA256 () =
  use netImplementation = System.Security.Cryptography.SHA256.Create()
  assertImplementationsEqual netImplementation.ComputeHash sha256 1_000

[<Test>]
let SHA384 () =
  use netImplementation = System.Security.Cryptography.SHA384.Create()
  assertImplementationsEqual netImplementation.ComputeHash sha384 1_000

[<Test>]
let SHA512 () =
  use netImplementation = System.Security.Cryptography.SHA512.Create()
  assertImplementationsEqual netImplementation.ComputeHash sha512 1_000

