# SHA
An implementation of the Secure Hash Standard in F#.

Implementation is based on [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) and testing is an implementation of [SHA Test Vectors for Hashing Byte-Oriented Messages](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)

## Do not use in production environments
This is a project I did for fun and my own education. While the implementations conform to the standard for byte-oriented implementations of the SHA family of functions, they do NOT utilize any kind of security protections against side channel analysis. If you are looking for something to use in any kind of production environment, use an actual cryptography library.

Additionally, you should not use SHA1 from any implementation, as it is no longer considered secure and is [no longer even a part of FIPS 180-4](https://csrc.nist.gov/news/2023/decision-to-revise-fips-180-4).

Finally, this code is optimized for readability of source code, NOT performance.

## Implemented hash functions:

- Secure Hash Algorithms
    - [x] SHA1 (functional and object oriented implementations)
    - [x] SHA256
    - [x] SHA224
    - [x] SHA384
    - [x] SHA512
    - [x] SHA512/t
      - [x] SHA512/224
      - [x] SHA512/256
- Message Digest Algorithms
    - [x] MD4
    - [x] MD5

## Reflections

This project helped me get more familiar with functional programming patterns. What really stood out to me was the dichotomy between the object oriented and functional implementations of SHA1. `Seq.fold` took a minute to wrap my head around, but once I got it right, the end product was far cleaner than the equivalent OO code. There were also far fewer temp variables in the functional approach, as everything was simply piped to the next step.

The SHA functions have many reusable components between them, so much of this project was simply creating generic functions. The most difficult part was creating functions that were generic between int32 and int64. For the majority of the development time of this project, `Ch`, `Parity` and `Maj` all had separate 32 and 64 bit implementations. Figuring out how to use type constraints properly was a huge challenge for me, though I was able to do it. Not all functions were able to be unified as one generic type (such as the padding functions), but even these benefitted from some generic helper functions.

I was never able to get the Monte Carlo tests working, as I could never figure out how to set it up properly ([Source document](https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/shs/shavs.pdf)). The implementations pass all other tests, so have no reason to believe they wouldn't also pass the Monte Carlo tests if I could just figure out how to set up such a test. If I were to revisit this project, I would want to actually figure that out and have that extra layer of validation.

### MD4/5Update

This is not a SHA function, yes, but I wanted to implement it so I did.

This was harder than I expected, simply because of the fact that MD5 is oriented around little endian numbers. I would have failed entirely if it weren't for [this project](https://github.com/MrBlackk/md5_sha256-512_debugger) that lays out what values to expect after each step.

I also broke off a lot of code into a `Utility` module, though I'm not sure that was actually necessary for a lot of the functions I did this to.

### Future work

I would like to implement the SHA-3 functions from [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final), but after reviewing that, the state array is nightmare fuel and, as this is just a project for fun, I likely will not be tackling that any time soon.