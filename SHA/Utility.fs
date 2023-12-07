[<AutoOpen>]
module internal Utility

/// Converts a uint64 into its component bytes in little endian order
let internal uint64ToBytes_le (value : uint64) : byte array =
  Array.init 8 (fun i ->
    let mask = 0xFFuL <<< (8*i)
    (mask &&& value) >>> (8*i) |> byte
  )
  
/// Converts a uint64 into its component bytes in big endian order
let internal uint64ToBytes_be =
  uint64ToBytes_le
  >> Array.rev

/// get bytes in Big Endian order
let internal int32ToBytes (h : uint32) =
  Array.init 4 (fun i -> h <<< (8*i) >>> 24 |> byte)

/// composes a Uint32 from the binary of four bytes in big-endian format
let internal bytesToUint32 (byte0:byte) (byte1:byte) (byte2:byte) (byte3:byte) =
    (uint32(byte0) <<< (8*3)) + (uint32(byte1) <<< (8*2)) + (uint32(byte2) <<< (8*1)) + (uint32(byte3) <<< (8*0))

/// composes a Uint64 from the binary of eight bytes in big-endian format
let internal bytesToUint64 (byte0:byte) (byte1:byte) (byte2:byte) (byte3:byte) (byte4:byte) (byte5:byte) (byte6:byte) (byte7:byte) =
    (uint64(byte0) <<< (8*7)) + (uint64(byte1) <<< (8*6)) + (uint64(byte2) <<< (8*5)) + (uint64(byte3) <<< (8*4)) +
    (uint64(byte4) <<< (8*3)) + (uint64(byte5) <<< (8*2)) + (uint64(byte6) <<< (8*1)) + (uint64(byte7) <<< (8*0))
    
/// given a byte array of length N, where N is a multiple of 4, combines the bytes into an array of uint32 words in little endian order
let internal byteArrToUint32_le (bytes : byte array) : uint32 array =
  let N = bytes.Length
  let outLength = N / 4
  Array.init outLength (fun t ->
      let byte0 = bytes[(t*4)+0]
      let byte1 = bytes[(t*4)+1]
      let byte2 = bytes[(t*4)+2]
      let byte3 = bytes[(t*4)+3]
      bytesToUint32 byte3 byte2 byte1 byte0
  )

/// Pads the data with a 1, followed by zeros and the data length
let internal pad (mlBytes : byte array) (data : byte array) =
  let bitwidth = mlBytes.Length * 8
  let paddingSize =
    let mlBytes = bitwidth / 8
    let baseLength = (data.Length + 1) % bitwidth
    ((bitwidth*2) - baseLength - mlBytes) % bitwidth
  Array.concat [|
    data
    [| 0x80uy |]
    Array.zeroCreate paddingSize
    mlBytes
  |]
 
/// Builds an array of fixed length based on a constructor function that generates values for the array.
/// Caches values once they are calculated to make sure values are never re-calculated
let internal buildArray<'TOut> size (constructor : (int -> 'TOut) -> int -> 'TOut) =
  if size <= 0 then invalidArg "size" "Array size should be greater than zero."
  let arr = Array.init size (fun _ -> None)
  let rec getValue index =
    arr[index] |> Option.defaultWith (fun _ ->
      let value = index |> constructor getValue
      arr[index] <- value |> Some
      value
    )
  Array.init size getValue

/// Takes a tuple and casts all values to 'T options, depending on if the cast is successful
let internal tupleToArray<'T> (t:obj) = 
  Microsoft.FSharp.Reflection.FSharpValue.GetTupleFields t
  |> Array.map (function
                | :? 'T as value -> Some value
                | _ -> None)

/// Takes a tuple and casts all values to 'T options.
/// Will throw an InvalidCastException if any elements are not of the required type
let internal tupleToHomogeneousArray<'T> (t:obj) =
  Microsoft.FSharp.Reflection.FSharpValue.GetTupleFields t
  |> Array.map (fun field -> field :?> 'T)
