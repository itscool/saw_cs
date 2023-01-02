// Hashes.cs - Fast implementations of common hashing methods.
//
// Includes the following:
//   CRC-32  - very fast checksum for data integrity verification
//             5333 Mb/s with Burst Compiler on i7-12700h
//             2327 Mb/s with Mono JIT on i7-12700h
//
//   MD5     - much slower than CRC-32, but a far more resilient checksum for
//             data integrity verification; much faster than SHA algorithms;
//             not suitable for cryptographic hashing due to extensive vulnerabilities
//             735 Mb/s with Burst Compiler on i7-12700h
//             463 Mb/s with Mono JIT on i7-12700h
//
//   SHA-1   - only included to validate against signatures or databases that still use it;
//             cryptographically broken and one should use an SHA-2 such as SHA-256 or
//             an SHA-3 instead
//             953 Mb/s with Burst Compiler on i7-12700h
//             293 Mb/s with Mono JIT on i7-12700h
//
//   SHA-256 - cryptographic hashing function from SHA-2 family
//             140 Mb/s with Burst Compiler on i7-12700h
//             28 Mb/s with Mono JIT on i7-12700h
//
// This is free and unencumbered software released into the public domain.
// 
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>

//-----------------------------------------------------------------------------------------------------------
// History
// - v1.00 - 01/01/23 - Initial release by Scott Williams

//-----------------------------------------------------------------------------------------------------------
// Notes
// - Intended as reference or as direct usage in .NET-based environments.
//   If used with Unity, the code is compatible with the Burst compiler.
//
// - Extremely fast implementations, though obviously not hand-optimized-per-platform-assembly-fast
//
// - Little Endian platforms validated only

//-----------------------------------------------------------------------------------------------------------
// Todo
// - More flexibility in CRC-32 implementation without losing simplicity of current API
//   (refin/refout support, smarter init/xorout)
// - SHA-256 optimization/rewrite
// - Would be nice to add processor intrinsic support for CRC-32/C when available as discussed in
//   https://stackoverflow.com/questions/17645167/implementing-sse-4-2s-crc32c-in-software/17646775#17646775
// - Would be nice to have intrinsic support for SHA-256

//#define INCLUDE_UNITY_TESTS

using System;
using System.Runtime.CompilerServices;

#if INCLUDE_UNITY_TESTS
using System.Diagnostics;
using Unity.Burst;
using Unity.Collections;
using Unity.Collections.LowLevel.Unsafe;
#endif

//-----------------------------------------------------------------------------------------------------------
// CRC-32
//-----------------------------------------------------------------------------------------------------------
// https://en.wikipedia.org/wiki/Cyclic_redundancy_check
// https://reveng.sourceforge.io/crc-catalogue/17plus.htm#crc.cat-bits.32

// This CRC-32 implementation has the following restrictions:
// - Table is meant for reverse polynomials for a well known optimization in the crc calculation
// - "refin" parameter of generalized CRC32 must be true (i.e. bits are input 0 - 31)
// - "refout" parameter of generalized CRC32 must be true (i.e. bits are output 0 - 31)
// - "init" and "xorout" are default to 0xffffffff and other configurations need done manually with this in mind
//   (i.e. if init is 0x00000000 then the initial crc should now be 0xffffffff)

public unsafe struct Crc32
{
    public const uint kCRC32 = 0xEDB88320;  // reversed - normal is 0x04C11DB7
    public const uint kCRC32C = 0x82F63B78;  // reversed - normal is 0x1EDC6F41

    fixed uint table[16 * 256];

    public Crc32(uint polynomial)
    {
        Configure(polynomial);
    }

    public void Configure(uint polynomial)
    {
        for (uint i = 0; i < 256; i++)
        {
            uint j = i;
            for (int t = 0; t < 16; t++)
            {
                for (int k = 0; k < 8; k++)
                    j = ((j & 1) * polynomial) ^ (j >> 1);
                table[(t * 256) + i] = j;
            }
        }
    }

    // Initial crc value is inverse, so the common case will be 0 instead of 0xffffffff
    // This can accumulate directly from the output of previous calls
    public unsafe uint Calculate(uint crc, byte* input, int offset, int length)
    {
        if (table[0] == 0 && table[1] == 0)  // default if forgot to configure
            Configure(kCRC32);

        uint* input32 = (uint*)(input + offset);
        crc = ~crc;
        while (length >= 16)
        {
            uint a = *input32++ ^ crc;
            uint b = *input32++;
            uint c = *input32++;
            uint d = *input32++;

            crc =
                table[0x000 + (d >> 24)] ^
                table[0x100 + ((d >> 16) & 0xff)] ^
                table[0x200 + ((d >> 8) & 0xff)] ^
                table[0x300 + (d & 0xff)] ^
                table[0x400 + (c >> 24)] ^
                table[0x500 + ((c >> 16) & 0xff)] ^
                table[0x600 + ((c >> 8) & 0xff)] ^
                table[0x700 + (c & 0xff)] ^
                table[0x800 + (b >> 24)] ^
                table[0x900 + ((b >> 16) & 0xff)] ^
                table[0xa00 + ((b >> 8) & 0xff)] ^
                table[0xb00 + (b & 0xff)] ^
                table[0xc00 + (a >> 24)] ^
                table[0xd00 + ((a >> 16) & 0xff)] ^
                table[0xe00 + ((a >> 8) & 0xff)] ^
                table[0xf00 + (a & 0xff)];

            length -= 16;
        }

        input = (byte*)input32;
        while (length-- > 0)
            crc = (crc >> 8) ^ table[(crc & 0xff) ^ *input++];

        return ~crc;
    }
}

//-----------------------------------------------------------------------------------------------------------
// SHA-1
//-----------------------------------------------------------------------------------------------------------
// https://en.wikipedia.org/wiki/SHA-1
// Ported from identically licensed https://github.com/983/SHA1

public unsafe struct Sha1Result
{
    public fixed byte hash[20];
}

public unsafe struct Sha1
{
    fixed uint state[5];
    fixed byte buf[64];
    fixed uint w[16];
    ulong n_bits;
    uint i;  //@chunk_pos

    const uint c0 = 0x5a827999;
    const uint c1 = 0x6ed9eba1;
    const uint c2 = 0x8f1bbcdc;
    const uint c3 = 0xca62c1d6;

    // One-shot call which can not be appended to
    public Sha1Result Calculate(byte* input, int length)
    {
        StreamStart();
        StreamAppend(input, length);
        var result = new Sha1Result();
        StreamFinish(ref result);
        return result;
    }

    public void StreamStart()
    {
        state[0] = 0x67452301;
        state[1] = 0xEFCDAB89;
        state[2] = 0x98BADCFE;
        state[3] = 0x10325476;
        state[4] = 0xC3D2E1F0;
        i = 0;
        n_bits = 0;
    }

    public void StreamAppend(byte* input, int length)
    {
        // fill up block if not full
        for (; length > 0 && (i & 63) != 0; length--)
        {
            add_byte_dont_count_bits(*input++);
            n_bits += 8;
        }

        // process full blocks
        for (; length >= 64; length -= 64)
        {
            process_block(input);
            input += 64;
            n_bits += 64 * 8;
        }

        // process remaining part of block
        for (; length > 0; length--)
        {
            add_byte_dont_count_bits(*input++);
            n_bits += 8;
        }
    }

    public void StreamFinish(ref Sha1Result sha1)
    {
        // hashed text ends with 0x80, some padding 0x00 and the length in bits
        add_byte_dont_count_bits(0x80);
        while ((i & 63) != 56) 
            add_byte_dont_count_bits(0x00);
        for (int j = 7; j >= 0; j--) 
            add_byte_dont_count_bits((byte)(n_bits >> (j * 8)));

        // Produce the final hash value (big-endian):
        for (int i = 0, j = 0; i < 5; i++)
        {
            sha1.hash[j++] = (byte)(state[i] >> 24);
            sha1.hash[j++] = (byte)(state[i] >> 16);
            sha1.hash[j++] = (byte)(state[i] >> 8);
            sha1.hash[j++] = (byte)state[i];
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static uint rol32(uint value, int count)
    {
        return (value << count) | (value >> (32 - count));
    }

    void add_byte_dont_count_bits(byte x)
    {
        buf[i++] = x;

        if (i >= 64)
        {
            i = 0;
            fixed (byte* b = buf)
                process_block(b);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static uint make_word(byte* p)
    {
        return ((uint)p[0] << 24) | ((uint)p[1] << 16) | ((uint)p[2] << 8) | p[3];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void SHA1_LOAD(int i)
    {
        w[i & 15] = rol32(w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15], 1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void SHA1_ROUND_0(uint v, ref uint u, uint x, uint y, ref uint z, int i)
    {
        z += ((u & (x ^ y)) ^ y) + w[i & 15] + c0 + rol32(v, 5);
        u = rol32(u, 30);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void SHA1_ROUND_1(uint v, ref uint u, uint x, uint y, ref uint z, int i)
    {
        SHA1_LOAD(i);
        z += ((u & (x ^ y)) ^ y) + w[i & 15] + c0 + rol32(v, 5);
        u = rol32(u, 30);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void SHA1_ROUND_2(uint v, ref uint u, uint x, uint y, ref uint z, int i)
    {
        SHA1_LOAD(i);
        z += (u ^ x ^ y) + w[i & 15] + c1 + rol32(v, 5);
        u = rol32(u, 30);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void SHA1_ROUND_3(uint v, ref uint u, uint x, uint y, ref uint z, int i)
    {
        SHA1_LOAD(i);
        z += (((u | x) & y) | (u & x)) + w[i & 15] + c2 + rol32(v, 5);
        u = rol32(u, 30);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void SHA1_ROUND_4(uint v, ref uint u, uint x, uint y, ref uint z, int i)
    {
        SHA1_LOAD(i);
        z += (u ^ x ^ y) + w[i & 15] + c3 + rol32(v, 5);
        u = rol32(u, 30);
    }

    void process_block(byte* ptr)
    {
        uint a = state[0];
        uint b = state[1];
        uint c = state[2];
        uint d = state[3];
        uint e = state[4];

        for (int i = 0; i < 16; i++) 
            w[i] = make_word(ptr + i * 4);

        SHA1_ROUND_0(a, ref b, c, d, ref e, 0);
        SHA1_ROUND_0(e, ref a, b, c, ref d, 1);
        SHA1_ROUND_0(d, ref e, a, b, ref c, 2);
        SHA1_ROUND_0(c, ref d, e, a, ref b, 3);
        SHA1_ROUND_0(b, ref c, d, e, ref a, 4);
        SHA1_ROUND_0(a, ref b, c, d, ref e, 5);
        SHA1_ROUND_0(e, ref a, b, c, ref d, 6);
        SHA1_ROUND_0(d, ref e, a, b, ref c, 7);
        SHA1_ROUND_0(c, ref d, e, a, ref b, 8);
        SHA1_ROUND_0(b, ref c, d, e, ref a, 9);
        SHA1_ROUND_0(a, ref b, c, d, ref e, 10);
        SHA1_ROUND_0(e, ref a, b, c, ref d, 11);
        SHA1_ROUND_0(d, ref e, a, b, ref c, 12);
        SHA1_ROUND_0(c, ref d, e, a, ref b, 13);
        SHA1_ROUND_0(b, ref c, d, e, ref a, 14);
        SHA1_ROUND_0(a, ref b, c, d, ref e, 15);
        SHA1_ROUND_1(e, ref a, b, c, ref d, 16);
        SHA1_ROUND_1(d, ref e, a, b, ref c, 17);
        SHA1_ROUND_1(c, ref d, e, a, ref b, 18);
        SHA1_ROUND_1(b, ref c, d, e, ref a, 19);
        SHA1_ROUND_2(a, ref b, c, d, ref e, 20);
        SHA1_ROUND_2(e, ref a, b, c, ref d, 21);
        SHA1_ROUND_2(d, ref e, a, b, ref c, 22);
        SHA1_ROUND_2(c, ref d, e, a, ref b, 23);
        SHA1_ROUND_2(b, ref c, d, e, ref a, 24);
        SHA1_ROUND_2(a, ref b, c, d, ref e, 25);
        SHA1_ROUND_2(e, ref a, b, c, ref d, 26);
        SHA1_ROUND_2(d, ref e, a, b, ref c, 27);
        SHA1_ROUND_2(c, ref d, e, a, ref b, 28);
        SHA1_ROUND_2(b, ref c, d, e, ref a, 29);
        SHA1_ROUND_2(a, ref b, c, d, ref e, 30);
        SHA1_ROUND_2(e, ref a, b, c, ref d, 31);
        SHA1_ROUND_2(d, ref e, a, b, ref c, 32);
        SHA1_ROUND_2(c, ref d, e, a, ref b, 33);
        SHA1_ROUND_2(b, ref c, d, e, ref a, 34);
        SHA1_ROUND_2(a, ref b, c, d, ref e, 35);
        SHA1_ROUND_2(e, ref a, b, c, ref d, 36);
        SHA1_ROUND_2(d, ref e, a, b, ref c, 37);
        SHA1_ROUND_2(c, ref d, e, a, ref b, 38);
        SHA1_ROUND_2(b, ref c, d, e, ref a, 39);
        SHA1_ROUND_3(a, ref b, c, d, ref e, 40);
        SHA1_ROUND_3(e, ref a, b, c, ref d, 41);
        SHA1_ROUND_3(d, ref e, a, b, ref c, 42);
        SHA1_ROUND_3(c, ref d, e, a, ref b, 43);
        SHA1_ROUND_3(b, ref c, d, e, ref a, 44);
        SHA1_ROUND_3(a, ref b, c, d, ref e, 45);
        SHA1_ROUND_3(e, ref a, b, c, ref d, 46);
        SHA1_ROUND_3(d, ref e, a, b, ref c, 47);
        SHA1_ROUND_3(c, ref d, e, a, ref b, 48);
        SHA1_ROUND_3(b, ref c, d, e, ref a, 49);
        SHA1_ROUND_3(a, ref b, c, d, ref e, 50);
        SHA1_ROUND_3(e, ref a, b, c, ref d, 51);
        SHA1_ROUND_3(d, ref e, a, b, ref c, 52);
        SHA1_ROUND_3(c, ref d, e, a, ref b, 53);
        SHA1_ROUND_3(b, ref c, d, e, ref a, 54);
        SHA1_ROUND_3(a, ref b, c, d, ref e, 55);
        SHA1_ROUND_3(e, ref a, b, c, ref d, 56);
        SHA1_ROUND_3(d, ref e, a, b, ref c, 57);
        SHA1_ROUND_3(c, ref d, e, a, ref b, 58);
        SHA1_ROUND_3(b, ref c, d, e, ref a, 59);
        SHA1_ROUND_4(a, ref b, c, d, ref e, 60);
        SHA1_ROUND_4(e, ref a, b, c, ref d, 61);
        SHA1_ROUND_4(d, ref e, a, b, ref c, 62);
        SHA1_ROUND_4(c, ref d, e, a, ref b, 63);
        SHA1_ROUND_4(b, ref c, d, e, ref a, 64);
        SHA1_ROUND_4(a, ref b, c, d, ref e, 65);
        SHA1_ROUND_4(e, ref a, b, c, ref d, 66);
        SHA1_ROUND_4(d, ref e, a, b, ref c, 67);
        SHA1_ROUND_4(c, ref d, e, a, ref b, 68);
        SHA1_ROUND_4(b, ref c, d, e, ref a, 69);
        SHA1_ROUND_4(a, ref b, c, d, ref e, 70);
        SHA1_ROUND_4(e, ref a, b, c, ref d, 71);
        SHA1_ROUND_4(d, ref e, a, b, ref c, 72);
        SHA1_ROUND_4(c, ref d, e, a, ref b, 73);
        SHA1_ROUND_4(b, ref c, d, e, ref a, 74);
        SHA1_ROUND_4(a, ref b, c, d, ref e, 75);
        SHA1_ROUND_4(e, ref a, b, c, ref d, 76);
        SHA1_ROUND_4(d, ref e, a, b, ref c, 77);
        SHA1_ROUND_4(c, ref d, e, a, ref b, 78);
        SHA1_ROUND_4(b, ref c, d, e, ref a, 79);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }
}

//-----------------------------------------------------------------------------------------------------------
// SHA-256
//-----------------------------------------------------------------------------------------------------------
// https://en.wikipedia.org/wiki/SHA-2
// Ported from identically licensed https://github.com/amosnier/sha-2

public unsafe struct Sha256Result
{
    public fixed byte hash[32];
}

public unsafe struct Sha256
{
    fixed byte chunk[kChunkSize];
    int chunk_pos;
    int space_left;
    int total_len;
    fixed uint h[8];
    const int kChunkSize = 64;
    const int kTotalLenSpace = 8;

    // One-shot call which can not be appended to
    public Sha256Result Calculate(byte* input, int length)
    {
        StreamStart();
        StreamAppend(input, length);
        var result = new Sha256Result();
        StreamFinish(ref result);
        return result;
    }

    public void StreamStart()
    {
        chunk_pos = 0;
        space_left = kChunkSize;
        total_len = 0;

        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;
    }

    public void StreamAppend(byte* input, int length)
    {
        total_len += length;

        fixed (uint* ht = h)
        fixed (byte* c = chunk)
        {
            while (length > 0)
            {
                // If the input chunks have sizes that are multiples of the calculation chunk size, no copies are
                // necessary. We operate directly on the input data instead.
                if (space_left == kChunkSize && length >= kChunkSize)
                {
                    consume_chunk(ht, input);
                    length -= kChunkSize;
                    input += kChunkSize;
                    continue;
                }

                // General case, no particular optimization
                int consumed_len = length < space_left ? length : space_left;
                for (int i = 0; i < consumed_len; i++)
                    chunk[chunk_pos + i] = input[i];
                space_left -= consumed_len;
                length -= consumed_len;
                input += consumed_len;
                if (space_left == 0)
                {
                    consume_chunk(ht, c);
                    chunk_pos = 0;
                    space_left = kChunkSize;
                }
                else
                    chunk_pos += consumed_len;
            }
        }
    }

    public void StreamFinish(ref Sha256Result sha256)
    {
	    // The current chunk cannot be full. Otherwise, it would already have be consumed. I.e. there is space left for
	    // at least one byte. The next step in the calculation is to add a single one-bit to the data.
        chunk[chunk_pos++] = 0x80;
        --space_left;

        fixed (uint* ht = h)
        fixed (byte* c = chunk)
        {
            // Now, the last step is to add the total data length at the end of the last chunk, and zero padding before
            // that. But we do not necessarily have enough space left. If not, we pad the current chunk with zeroes, and add
            // an extra chunk at the end.
            if (space_left < kTotalLenSpace)
            {
                for (int i = 0; i < space_left; i++)
                    chunk[chunk_pos + i] = 0;
                consume_chunk(ht, c);
                chunk_pos = 0;
                space_left = kChunkSize;
            }
            int left = space_left - kTotalLenSpace;
            for (int i = 0; i < left; i++)
                chunk[chunk_pos + i] = 0;
            chunk_pos += left;
            int len = total_len;
            chunk[chunk_pos + 7] = (byte)(len << 3);
            len >>= 5;

            for (int i = 6; i >= 0; --i)
            {
                chunk[chunk_pos + i] = (byte)len;
                len >>= 8;
            }
            consume_chunk(ht, c);
        }

        // Produce the final hash value (big-endian):
        for (int i = 0, j = 0; i < 8; i++)
        {
            sha256.hash[j++] = (byte)(h[i] >> 24);
            sha256.hash[j++] = (byte)(h[i] >> 16);
            sha256.hash[j++] = (byte)(h[i] >> 8);
            sha256.hash[j++] = (byte)h[i];
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static uint right_rot(uint value, int count)
    {
        return value >> count | value << (32 - count);
    }

    static void consume_chunk(uint* h, byte* p)
    {
        uint i, j;

        uint* ah = stackalloc uint[8];
        for (i = 0; i < 8; i++)
            ah[i] = h[i];

        uint* w = stackalloc uint[16];
        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < 16; j++)
            {
                if (i == 0)
                {
                    w[j] = ((uint)p[0] << 24) | ((uint)p[1] << 16) | ((uint)p[2] << 8) | (uint)p[3];
                    p += 4;
                }
                else
                {
                    uint s0Pre = right_rot(w[(j + 1) & 0xf], 7) ^
                        right_rot(w[(j + 1) & 0xf], 18) ^
                        (w[(j + 1) & 0xf] >> 3);
                    uint s1Pre = right_rot(w[(j + 14) & 0xf], 17) ^
                        right_rot(w[(j + 14) & 0xf], 19) ^
                        (w[(j + 14) & 0xf] >> 10);
                    w[j] = w[j] + s0Pre + w[(j + 9) & 0xf] + s1Pre;
                }

                uint s1 = right_rot(ah[4], 6) ^ right_rot(ah[4], 11) ^ right_rot(ah[4], 25);
                uint ch = (ah[4] & ah[5]) ^ (~ah[4] & ah[6]);

                uint* k = stackalloc uint[]
                {
                    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
                };

                uint temp1 = ah[7] + s1 + ch + k[i << 4 | j] + w[j];
                uint s0 = right_rot(ah[0], 2) ^ right_rot(ah[0], 13) ^ right_rot(ah[0], 22);
                uint maj = (ah[0] & ah[1]) ^ (ah[0] & ah[2]) ^ (ah[1] & ah[2]);
                uint temp2 = s0 + maj;

                ah[7] = ah[6];
                ah[6] = ah[5];
                ah[5] = ah[4];
                ah[4] = ah[3] + temp1;
                ah[3] = ah[2];
                ah[2] = ah[1];
                ah[1] = ah[0];
                ah[0] = temp1 + temp2;
            }
        }

        for (i = 0; i < 8; i++)
            h[i] += ah[i];
    }
}

//-----------------------------------------------------------------------------------------------------------
// MD5
//-----------------------------------------------------------------------------------------------------------
// https://en.wikipedia.org/wiki/MD5
// Ported from identically licensed https://github.com/galenguyer/md5/blob/main/md5.c

public unsafe struct Md5Result
{
    public fixed byte hash[16];
}

public unsafe struct Md5
{
    uint a;
    uint b;
    uint c;
    uint d;
    fixed int count[2];
    fixed uint block[16];
    fixed byte chunk[64];

    // One-shot call which can not be appended to
    public Md5Result Calculate(byte* input, int length)
    {
        StreamStart();
        StreamAppend(input, length);
        var result = new Md5Result();
        StreamFinish(ref result);
        return result;
    }

    public void StreamStart()
    {
        a = 0x67452301;
        b = 0xefcdab89;
        c = 0x98badcfe;
        d = 0x10325476;

        count[0] = 0;
        count[1] = 0;
    }

    public void StreamAppend(byte* input, int length)
    {
        int saved_low = count[0];

        if ((count[0] = ((saved_low + length) & 0x1fffffff)) < saved_low)
            count[1]++;

        count[1] += length >> 29;

        int used = saved_low & 0x3f;

        if (used > 0)
        {
            int free = 64 - used;

            if (length < free)
            {
                for (int i = 0; i < length; i++)
                    chunk[used + i] = input[i];
                return;
            }

            for (int i = 0; i < free; i++)
                chunk[used + i] = input[i];
            input += free;
            length -= free;
            fixed (byte* c = chunk)
                transform(c, 64);
        }

        if (length >= 64)
        {
            input = transform(input, length & ~0x3f);
            length = length & 0x3f;
        }

        for (int i = 0; i < length; i++)
            chunk[i] = input[i];
    }

    public void StreamFinish(ref Md5Result md5)
    {
        int used = count[0] & 0x3f;
        chunk[used++] = 0x80;
        int free = 64 - used;

        if (free < 8)
        {
            for (int i = 0; i < free; i++)
                chunk[used + i] = 0;
            fixed (byte* c = chunk)
                transform(c, 64);
            used = 0;
            free = 64;
        }

        for (int i = 0; i < free - 8; i++)
            chunk[used + i] = 0;

        count[0] <<= 3;
        chunk[56] = (byte)(count[0]);
        chunk[57] = (byte)(count[0] >> 8);
        chunk[58] = (byte)(count[0] >> 16);
        chunk[59] = (byte)(count[0] >> 24);
        chunk[60] = (byte)(count[1]);
        chunk[61] = (byte)(count[1] >> 8);
        chunk[62] = (byte)(count[1] >> 16);
        chunk[63] = (byte)(count[1] >> 24);

        fixed(byte* c = chunk)
            transform(c, 64);

        md5.hash[0] = (byte)(a);
        md5.hash[1] = (byte)(a >> 8);
        md5.hash[2] = (byte)(a >> 16);
        md5.hash[3] = (byte)(a >> 24);
        md5.hash[4] = (byte)(b);
        md5.hash[5] = (byte)(b >> 8);
        md5.hash[6] = (byte)(b >> 16);
        md5.hash[7] = (byte)(b >> 24);
        md5.hash[8] = (byte)(c);
        md5.hash[9] = (byte)(c >> 8);
        md5.hash[10] = (byte)(c >> 16);
        md5.hash[11] = (byte)(c >> 24);
        md5.hash[12] = (byte)(d);
        md5.hash[13] = (byte)(d >> 8);
        md5.hash[14] = (byte)(d >> 16);
        md5.hash[15] = (byte)(d >> 24);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static uint ROTATE_LEFT(uint value, int count)
    {
        return (value << count) | (value >> (32 - count));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void STEP_F(ref uint a, uint b, uint c, uint d, uint x, uint t, int s)
    {
        a += (d ^ (b & (c ^ d))) + x + t;
        a = ROTATE_LEFT(a, s);
        a += b;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void STEP_G(ref uint a, uint b, uint c, uint d, uint x, uint t, int s)
    {
        a += (c ^ (d & (b ^ c))) + x + t;
        a = ROTATE_LEFT(a, s);
        a += b;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void STEP_H(ref uint a, uint b, uint c, uint d, uint x, uint t, int s)
    {
        a += (b ^ c ^ d) + x + t;
        a = ROTATE_LEFT(a, s);
        a += b;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void STEP_I(ref uint a, uint b, uint c, uint d, uint x, uint t, int s)
    {
        a += (c ^ (b | ~d)) + x + t;
        a = ROTATE_LEFT(a, s);
        a += b;
    }

    byte* transform(byte* data, int size)
    {
        // data access through ptr is the only part needing changed if big endian ever needed supported
        uint* ptr = (uint*)data;

        do
        {
            uint aa = a;
            uint bb = b;
            uint cc = c;
            uint dd = d;

            STEP_F(ref a, b, c, d, block[0] = ptr[0], 0xd76aa478, 7);
            STEP_F(ref d, a, b, c, block[1] = ptr[1], 0xe8c7b756, 12);
            STEP_F(ref c, d, a, b, block[2] = ptr[2], 0x242070db, 17);
            STEP_F(ref b, c, d, a, block[3] = ptr[3], 0xc1bdceee, 22);
            STEP_F(ref a, b, c, d, block[4] = ptr[4], 0xf57c0faf, 7);
            STEP_F(ref d, a, b, c, block[5] = ptr[5], 0x4787c62a, 12);
            STEP_F(ref c, d, a, b, block[6] = ptr[6], 0xa8304613, 17);
            STEP_F(ref b, c, d, a, block[7] = ptr[7], 0xfd469501, 22);
            STEP_F(ref a, b, c, d, block[8] = ptr[8], 0x698098d8, 7);
            STEP_F(ref d, a, b, c, block[9] = ptr[9], 0x8b44f7af, 12);
            STEP_F(ref c, d, a, b, block[10] = ptr[10], 0xffff5bb1, 17);
            STEP_F(ref b, c, d, a, block[11] = ptr[11], 0x895cd7be, 22);
            STEP_F(ref a, b, c, d, block[12] = ptr[12], 0x6b901122, 7);
            STEP_F(ref d, a, b, c, block[13] = ptr[13], 0xfd987193, 12);
            STEP_F(ref c, d, a, b, block[14] = ptr[14], 0xa679438e, 17);
            STEP_F(ref b, c, d, a, block[15] = ptr[15], 0x49b40821, 22);

            STEP_G(ref a, b, c, d, block[1], 0xf61e2562, 5);
            STEP_G(ref d, a, b, c, block[6], 0xc040b340, 9);
            STEP_G(ref c, d, a, b, block[11], 0x265e5a51, 14);
            STEP_G(ref b, c, d, a, block[0], 0xe9b6c7aa, 20);
            STEP_G(ref a, b, c, d, block[5], 0xd62f105d, 5);
            STEP_G(ref d, a, b, c, block[10], 0x02441453, 9);
            STEP_G(ref c, d, a, b, block[15], 0xd8a1e681, 14);
            STEP_G(ref b, c, d, a, block[4], 0xe7d3fbc8, 20);
            STEP_G(ref a, b, c, d, block[9], 0x21e1cde6, 5);
            STEP_G(ref d, a, b, c, block[14], 0xc33707d6, 9);
            STEP_G(ref c, d, a, b, block[3], 0xf4d50d87, 14);
            STEP_G(ref b, c, d, a, block[8], 0x455a14ed, 20);
            STEP_G(ref a, b, c, d, block[13], 0xa9e3e905, 5);
            STEP_G(ref d, a, b, c, block[2], 0xfcefa3f8, 9);
            STEP_G(ref c, d, a, b, block[7], 0x676f02d9, 14);
            STEP_G(ref b, c, d, a, block[12], 0x8d2a4c8a, 20);

            STEP_H(ref a, b, c, d, block[5], 0xfffa3942, 4);
            STEP_H(ref d, a, b, c, block[8], 0x8771f681, 11);
            STEP_H(ref c, d, a, b, block[11], 0x6d9d6122, 16);
            STEP_H(ref b, c, d, a, block[14], 0xfde5380c, 23);
            STEP_H(ref a, b, c, d, block[1], 0xa4beea44, 4);
            STEP_H(ref d, a, b, c, block[4], 0x4bdecfa9, 11);
            STEP_H(ref c, d, a, b, block[7], 0xf6bb4b60, 16);
            STEP_H(ref b, c, d, a, block[10], 0xbebfbc70, 23);
            STEP_H(ref a, b, c, d, block[13], 0x289b7ec6, 4);
            STEP_H(ref d, a, b, c, block[0], 0xeaa127fa, 11);
            STEP_H(ref c, d, a, b, block[3], 0xd4ef3085, 16);
            STEP_H(ref b, c, d, a, block[6], 0x04881d05, 23);
            STEP_H(ref a, b, c, d, block[9], 0xd9d4d039, 4);
            STEP_H(ref d, a, b, c, block[12], 0xe6db99e5, 11);
            STEP_H(ref c, d, a, b, block[15], 0x1fa27cf8, 16);
            STEP_H(ref b, c, d, a, block[2], 0xc4ac5665, 23);

            STEP_I(ref a, b, c, d, block[0], 0xf4292244, 6);
            STEP_I(ref d, a, b, c, block[7], 0x432aff97, 10);
            STEP_I(ref c, d, a, b, block[14], 0xab9423a7, 15);
            STEP_I(ref b, c, d, a, block[5], 0xfc93a039, 21);
            STEP_I(ref a, b, c, d, block[12], 0x655b59c3, 6);
            STEP_I(ref d, a, b, c, block[3], 0x8f0ccc92, 10);
            STEP_I(ref c, d, a, b, block[10], 0xffeff47d, 15);
            STEP_I(ref b, c, d, a, block[1], 0x85845dd1, 21);
            STEP_I(ref a, b, c, d, block[8], 0x6fa87e4f, 6);
            STEP_I(ref d, a, b, c, block[15], 0xfe2ce6e0, 10);
            STEP_I(ref c, d, a, b, block[6], 0xa3014314, 15);
            STEP_I(ref b, c, d, a, block[13], 0x4e0811a1, 21);
            STEP_I(ref a, b, c, d, block[4], 0xf7537e82, 6);
            STEP_I(ref d, a, b, c, block[11], 0xbd3af235, 10);
            STEP_I(ref c, d, a, b, block[2], 0x2ad7d2bb, 15);
            STEP_I(ref b, c, d, a, block[9], 0xeb86d391, 21);

            a += aa;
            b += bb;
            c += cc;
            d += dd;

            ptr += 16;
            size -= 64;
        } while (size > 0);

        return (byte*)ptr;
    }
}



#if INCLUDE_UNITY_TESTS

//-----------------------------------------------------------------------------------------------------------
// Tests
//-----------------------------------------------------------------------------------------------------------
// - Hardly fancy and barely automated, these must be manually validated
// - Dependency on Unity Engine

[BurstCompile(CompileSynchronously = true)]
public unsafe class TestHashes
{
    const int kWarmup = 1;
    const int kCycles = 4;

    [BurstCompile(CompileSynchronously = true)]
    static uint TestCrc32Burst(ref Crc32 crc32, ref NativeArray<byte> input, int cycles)
    {
        uint output = 0;
        for (int i = 0; i < cycles; i++)
            output = crc32.Calculate(0, (byte*)input.GetUnsafePtr(), 0, input.Length);
        return output;
    }

    public static void TestCrc32(int length)
    {
        var input = new NativeArray<byte>(length, Allocator.Temp, NativeArrayOptions.UninitializedMemory);
        for (int i = 0; i < length; i++)
            input[i] = (byte)UnityEngine.Random.Range(0, 256);

        Crc32 crc32 = new Crc32(Crc32.kCRC32);
        Stopwatch timer = new Stopwatch();

        uint output = 0;
        for (int i = 0; i < kWarmup; i++)
            crc32.Calculate(0, (byte*)input.GetUnsafePtr(), 0, input.Length);
        timer.Restart();
        for (int i = 0; i < kCycles; i++)
            output = crc32.Calculate(0, (byte*)input.GetUnsafePtr(), 0, input.Length);
        timer.Stop();
        long time = timer.ElapsedMilliseconds;

        uint outputBurst = 0;
        TestCrc32Burst(ref crc32, ref input, kWarmup);
        timer.Restart();
        outputBurst = TestCrc32Burst(ref crc32, ref input, kCycles);
        timer.Stop();
        long timeBurst = timer.ElapsedMilliseconds;

        uint outputSlow = 0;
        timer.Restart();
        for (int i = 0; i < input.Length; i += 4)
            outputSlow = crc32.Calculate(outputSlow, (byte*)input.GetUnsafePtr(), i, 4);
        timer.Stop();
        long timeSlow = timer.ElapsedMilliseconds;

        byte* vec = stackalloc byte[9];
        for (int i = 0; i < 9; i++)
            vec[i] = (byte)('1' + i);

        Crc32 crc32c = new Crc32(Crc32.kCRC32C);
        uint validateCRC32 = crc32.Calculate(0, vec, 0, 9);
        uint validateCRC32C = crc32c.Calculate(0, vec, 0, 9);

        UnityEngine.Debug.Log($"High resolution timing is {Stopwatch.IsHighResolution}\n"
            + $"CRC32 JIT time is {time} at {input.Length * kCycles / time * 1000 / 1024 / 1024}Mb/s\n"
            + $"CRC32 Burst time is {timeBurst} at {input.Length * kCycles / timeBurst * 1000 / 1024 / 1024}Mb/s\n"
            + $"CRC32 slow time is {timeSlow} at {input.Length * kCycles / timeSlow * 1000 / 1024 / 1024}Mb/s\n"
            + $"CRC32 JIT result is 0x{output:X8}\n"
            + $"CRC32 Burst result is 0x{outputBurst:X8}\n"
            + $"CRC32 slow result is 0x{outputSlow:X8}\n"
            + $"CRC32 slow for 123456789 is 0x{validateCRC32:X8} and should be 0xCBF43926\n"
            + $"CRC32C slow for 123456789 is 0x{validateCRC32C:X8} and should be 0xE3069283\n"
            );
    }

    [BurstCompile(CompileSynchronously = true)]
    static Sha256Result TestSha256Burst(ref Sha256 sha, ref NativeArray<byte> input, int cycles)
    {
        Sha256Result result = new Sha256Result();
        for (int i = 0; i < cycles; i++)
            result = sha.Calculate((byte*)input.GetUnsafePtr(), input.Length);
        return result;
    }

    static Sha256Result TestSha256Jit(ref Sha256 sha, ref NativeArray<byte> input, int cycles)
    {
        Sha256Result result = new Sha256Result();
        for (int i = 0; i < cycles; i++)
            result = sha.Calculate((byte*)input.GetUnsafePtr(), input.Length);
        return result;
    }

    public static void TestSha256()
    {
        HashTestString[] strings = new HashTestString[]
        {
            new HashTestString("",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            new HashTestString("abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            new HashTestString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "a8ae6e6ee929abea3afcfc5258c8ccd6f85273e0d4626d26c7279f3250f77c8e"),
            new HashTestString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
                "057ee79ece0b9a849552ab8d3c335fe9a5f1c46ef5f1d9b190c295728628299c"),
            new HashTestString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
                "2a6ad82f3620d3ebe9d678c812ae12312699d673240d5be8fac0910a70000d93"),
            new HashTestString("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
            new HashTestString("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
        };

        string log = "";
        Sha256 sha256 = new Sha256();
        for (int i = 0; i < strings.Length; i++)
        {
            var hash = sha256.Calculate(strings[i].input.GetUnsafePtr(), strings[i].input.Length);
            string hashString = HashToString(hash.hash, 32);
            log += $"({i}) {(hashString == strings[i].expectedHash.ToUpper() ? "SUCCESS" : "ERROR")} {strings[i].input}\n";
            log += $"        {hashString} <-> {strings[i].expectedHash}\n";
        }

        HashTestData[] datas = new HashTestData[]
        {
            new HashTestData(new byte[]{ 0xbd }, "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b"),
            new HashTestData(new byte[]{ 0xc9, 0x8c, 0x8e, 0x55 }, "7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504"),
            new HashTestData(0x00, 55, "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7"),
            new HashTestData(0x00, 56, "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb"),
            new HashTestData(0x00, 57, "65a16cb7861335d5ace3c60718b5052e44660726da4cd13bb745381b235a1785"),
            new HashTestData(0x00, 64, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
            new HashTestData(0x00, 1000, "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53"),
            new HashTestData(0x41, 1000, "c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4"),
            new HashTestData(0x55, 1005, "f4d62ddec0f3dd90ea1380fa16a5ff8dc4c54b21740650f24afc4120903552b0"),
            new HashTestData(0x00, 1000000, "d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc8025"),
            new HashTestData(0x5a, 536870912, "15a1868c12cc53951e182344277447cd0979536badcc512ad24c67e9b2d4f3dd"),
        };

        for (int i = 0; i < datas.Length; i++)
        {
            var hash = sha256.Calculate((byte*)datas[i].input.GetUnsafePtr(), datas[i].input.Length);
            string hashString = HashToString(hash.hash, 32);
            log += $"({i}) {(hashString == datas[i].expectedHash.ToUpper() ? "SUCCESS" : "ERROR")}\n";
            log += $"        {hashString} <-> {datas[i].expectedHash}\n";
        }

        Stopwatch timer = new Stopwatch();

        TestSha256Jit(ref sha256, ref datas[9].input, kWarmup);
        timer.Restart();
        TestSha256Jit(ref sha256, ref datas[9].input, kCycles);
        timer.Stop();
        long timeJit = timer.ElapsedMilliseconds;

        TestSha256Burst(ref sha256, ref datas[9].input, kWarmup);
        timer.Restart();
        TestSha256Burst(ref sha256, ref datas[9].input, kCycles);
        timer.Stop();
        long timeBurst = timer.ElapsedMilliseconds;

        log += $"Jit time is {timeJit} at {datas[9].input.Length * kCycles / timeJit * 1000 / 1024 / 1024}Mb/s\n";
        log += $"Burst time is {timeBurst} at {datas[9].input.Length * kCycles / timeBurst * 1000 / 1024 / 1024}Mb/s";

        UnityEngine.Debug.Log(log);
    }

    [BurstCompile(CompileSynchronously = true)]
    static Sha1Result TestSha1Burst(ref Sha1 sha, ref NativeArray<byte> input, int cycles)
    {
        Sha1Result result = new Sha1Result();
        for (int i = 0; i < cycles; i++)
            result = sha.Calculate((byte*)input.GetUnsafePtr(), input.Length);
        return result;
    }

    static Sha1Result TestSha1Jit(ref Sha1 sha, ref NativeArray<byte> input, int cycles)
    {
        Sha1Result result = new Sha1Result();
        for (int i = 0; i < cycles; i++)
            result = sha.Calculate((byte*)input.GetUnsafePtr(), input.Length);
        return result;
    }

    public static void TestSha1()
    {
        HashTestString[] strings = new HashTestString[]
        {
            new HashTestString("",
                "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            new HashTestString("abc",
                "a9993e364706816aba3e25717850c26c9cd0d89d"),
            new HashTestString("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
            new HashTestString("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "a49b2446a02c645bf419f995b67091253a04a259"),
        };

        string log = "";
        Sha1 sha1 = new Sha1();
        for (int i = 0; i < strings.Length; i++)
        {
            var hash = sha1.Calculate(strings[i].input.GetUnsafePtr(), strings[i].input.Length);
            string hashString = HashToString(hash.hash, 20);
            log += $"({i}) {(hashString == strings[i].expectedHash.ToUpper() ? "SUCCESS" : "ERROR")} {strings[i].input}\n";
            log += $"        {hashString} <-> {strings[i].expectedHash}\n";
        }

        HashTestData[] datas = new HashTestData[]
        {
            new HashTestData(0x61, 1000000, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"),
        };

        for (int i = 0; i < datas.Length; i++)
        {
            var hash = sha1.Calculate((byte*)datas[i].input.GetUnsafePtr(), datas[i].input.Length);
            string hashString = HashToString(hash.hash, 20);
            log += $"({i}) {(hashString == datas[i].expectedHash.ToUpper() ? "SUCCESS" : "ERROR")}\n";
            log += $"        {hashString} <-> {datas[i].expectedHash}\n";
        }

        Stopwatch timer = new Stopwatch();

        TestSha1Jit(ref sha1, ref datas[0].input, kWarmup);
        timer.Restart();
        TestSha1Jit(ref sha1, ref datas[0].input, kCycles);
        timer.Stop();
        long timeJit = timer.ElapsedMilliseconds;

        TestSha1Burst(ref sha1, ref datas[0].input, kWarmup);
        timer.Restart();
        TestSha1Burst(ref sha1, ref datas[0].input, kCycles);
        timer.Stop();
        long timeBurst = timer.ElapsedMilliseconds;

        log += $"Jit time is {timeJit} at {datas[0].input.Length * kCycles / timeJit * 1000 / 1024 / 1024}Mb/s\n";
        log += $"Burst time is {timeBurst} at {datas[0].input.Length * kCycles / timeBurst * 1000 / 1024 / 1024}Mb/s";

        UnityEngine.Debug.Log(log);
    }

    [BurstCompile(CompileSynchronously = true)]
    static Md5Result TestMd5Burst(ref Md5 md5, ref NativeArray<byte> input, int cycles)
    {
        Md5Result result = new Md5Result();
        for (int i = 0; i < cycles; i++)
            result = md5.Calculate((byte*)input.GetUnsafePtr(), input.Length);
        return result;
    }

    static Md5Result TestMd5Jit(ref Md5 md5, ref NativeArray<byte> input, int cycles)
    {
        Md5Result result = new Md5Result();
        for (int i = 0; i < cycles; i++)
            result = md5.Calculate((byte*)input.GetUnsafePtr(), input.Length);
        return result;
    }

    public static void TestMd5()
    {
        HashTestString[] strings = new HashTestString[]
        {
            new HashTestString("",
                "d41d8cd98f00b204e9800998ecf8427e"),
            new HashTestString("a",
                "0cc175b9c0f1b6a831c399e269772661"),
            new HashTestString("abc",
                "900150983cd24fb0d6963f7d28e17f72"),
            new HashTestString("message digest",
                "f96b697d7cb7938d525a2f31aaf161d0"),
            new HashTestString("abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b"),
            new HashTestString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f"),
            new HashTestString("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a"),
        };

        string log = "";
        Md5 md5 = new Md5();
        for (int i = 0; i < strings.Length; i++)
        {
            var hash = md5.Calculate(strings[i].input.GetUnsafePtr(), strings[i].input.Length);
            string hashString = HashToString(hash.hash, 16);
            log += $"({i}) {(hashString == strings[i].expectedHash.ToUpper() ? "SUCCESS" : "ERROR")} {strings[i].input}\n";
            log += $"        {hashString} <-> {strings[i].expectedHash}\n";
        }

        HashTestData[] datas = new HashTestData[]
        {
            new HashTestData(0x61, 1024 * 1024 * 16, "f4820540fc0ac02750739896fe028d56"),
        };

        for (int i = 0; i < datas.Length; i++)
        {
            var hash = md5.Calculate((byte*)datas[i].input.GetUnsafePtr(), datas[i].input.Length);
            string hashString = HashToString(hash.hash, 16);
            log += $"({i}) {(hashString == datas[i].expectedHash.ToUpper() ? "SUCCESS" : "ERROR")}\n";
            log += $"        {hashString} <-> {datas[i].expectedHash}\n";
        }

        Stopwatch timer = new Stopwatch();

        TestMd5Jit(ref md5, ref datas[0].input, kWarmup);
        timer.Restart();
        TestMd5Jit(ref md5, ref datas[0].input, kCycles);
        timer.Stop();
        long timeJit = timer.ElapsedMilliseconds;

        TestMd5Burst(ref md5, ref datas[0].input, kWarmup);
        timer.Restart();
        TestMd5Burst(ref md5, ref datas[0].input, kCycles);
        timer.Stop();
        long timeBurst = timer.ElapsedMilliseconds;

        log += $"Jit time is {timeJit} at {datas[0].input.Length * kCycles / timeJit * 1000 / 1024 / 1024}Mb/s\n";
        log += $"Burst time is {timeBurst} at {datas[0].input.Length * kCycles / timeBurst * 1000 / 1024 / 1024}Mb/s";

        UnityEngine.Debug.Log(log);
    }

    struct HashTestData
    {
        public HashTestData(byte[] inData, string outData)
        {
            input = new NativeArray<byte>(inData, Allocator.Temp);
            expectedHash = outData;
        }

        public HashTestData(byte inData, int repeat, string outData)
        {
            input = new NativeArray<byte>(repeat, Allocator.Temp, NativeArrayOptions.UninitializedMemory);
            for (int i = 0; i < repeat; i++)
                input[i] = inData;
            expectedHash = outData;
        }

        public NativeArray<byte> input;
        public string expectedHash;
    };

    struct HashTestString
    {
        public HashTestString(string inData, string outData)
        {
            input = new NativeText(inData, Allocator.Temp);
            expectedHash = outData;
        }

        public NativeText input;
        public string expectedHash;
    };

    static string HashToString(byte* hash, int hashLen)
    {
        string ret = "";
        for (int i = 0; i < hashLen; i++)
            ret += $"{hash[i]:X2}";
        return ret;
    }
}
#endif
