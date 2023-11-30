namespace SHATests

open Microsoft.FSharp.Core
open System.Text.RegularExpressions

type RspEntry = {
  Len : int
  Msg : byte array
  MD : byte array
  }

module RspReader =
  let stringToByteArr (str : string) =
    [| 0..2..(str.Length-2) |]
    |> Array.map (fun i -> str.Substring(i, 2))
    |> Array.map (fun str -> System.Byte.Parse(str, System.Globalization.NumberStyles.HexNumber))

  let private RspRegex =
    let options = RegexOptions.IgnoreCase ||| RegexOptions.Multiline ||| RegexOptions.Compiled
    Regex(@"Len = (\d+)\nMsg = ([0-9a-f]*)\nMD = ([0-9a-f]+)$", options)

  let readRspFromFile filename =
    System.IO.File.ReadAllText(filename).ReplaceLineEndings("\n")
    |> RspRegex.Matches
    |> Seq.choose (fun m ->
        match System.Int32.TryParse m.Groups[1].Value with
        | false, _ -> None
        | true, len ->
        let msg = m.Groups[2].Value |> stringToByteArr |> Array.take (len / 8)
        let md = m.Groups[3].Value |> stringToByteArr
        Some { RspEntry.Len = len; Msg = msg; MD = md }
      )