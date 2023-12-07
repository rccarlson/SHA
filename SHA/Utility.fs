[<AutoOpen>]
module internal Utility

/// Converts a uint64 into its component bytes in little endian order
let uint64ToBytes_le (value : uint64) : byte array =
  Array.init 8 (fun i ->
    let mask = 0xFFuL <<< (8*i)
    (mask &&& value) >>> (8*i) |> byte
  )
  
/// Converts a uint64 into its component bytes in big endian order
let uint64ToBytes_be = uint64ToBytes_le >> Array.rev

/// get bytes in Big Endian order
let int32ToBytes (value : uint32) = Array.init 4 (fun i -> value <<< (8*i) >>> 24 |> byte)

let inline private buildNumberFromBytes converter zero (bytes : byte array) =
  bytes
  |> Array.rev
  |> Array.fold (fun (i, state) curr ->
      let currValue = (converter curr) <<< (8 * i)
      (i + 1, state + currValue)
    )
    (0,zero)
  |> snd

///// composes a Uint32 from the binary of four bytes in big-endian format
let bytesToUint32 = buildNumberFromBytes uint32 0u

/// composes a Uint64 from the binary of eight bytes in big-endian format
let bytesToUint64 = buildNumberFromBytes uint64 0uL
    
/// given a byte array of length N, where N is a multiple of 4, combines the bytes into an array of uint32 words in little endian order
let byteArrToUint32_le (bytes : byte array) : uint32 array =
  let outLength = bytes.Length / 4
  Array.init outLength (fun t ->
      Array.sub bytes (t*4) 4
      |> Array.rev
      |> bytesToUint32
  )

/// Pads the data with a 1, followed by zeros and the data length
let pad (mlBytes : byte array) (data : byte array) =
  let paddingSize =
    let bitwidth = mlBytes.Length * 8
    let mlBytes = bitwidth / 8
    let baseLength = (data.Length + 1) % bitwidth
    ((bitwidth*2) - baseLength - mlBytes) % bitwidth
  Array.concat [|
    data
    [| 0x80uy |]
    Array.zeroCreate paddingSize
    mlBytes
  |]
 
/// Builds an array of fixed length based on a generator function that generates values for the array based on its index.
/// Caches values once they are calculated to make sure values are never re-calculated
let buildArray<'TOut> size (generator : (int -> 'TOut) -> int -> 'TOut) =
  if size <= 0 then invalidArg "size" "Array size should be greater than zero."
  let arr = Array.init size (fun _ -> None)
  let rec getValue index =
    arr[index] |> Option.defaultWith (fun _ ->
      let value = index |> generator getValue
      arr[index] <- value |> Some
      value
    )
  Array.init size getValue
  
/// Takes a tuple and casts all values to 'T options, depending on if the cast is successful
let tupleToArray<'T> = 
  Microsoft.FSharp.Reflection.FSharpValue.GetTupleFields
  >> Array.map (function | :? 'T as value -> Some value | _ -> None)

/// Takes a tuple and casts all values to 'T options.
/// Will throw an InvalidCastException if any elements are not of the required type
let tupleToHomogeneousArray<'T> (t:obj) =
  Microsoft.FSharp.Reflection.FSharpValue.GetTupleFields t
  |> Array.map (fun field -> field :?> 'T)

/// Creates a tuple from the given array
let listToTuple<'TIn, 'TOut> (arr : 'TIn array)=
  let objArray = arr |> Array.map (fun x -> x :> obj)
  let tupleType =
    arr
    |> Array.map (fun o -> o.GetType())
    |> Microsoft.FSharp.Reflection.FSharpType.MakeTupleType
  Microsoft.FSharp.Reflection.FSharpValue.MakeTuple(objArray, tupleType) :?> 'TOut
