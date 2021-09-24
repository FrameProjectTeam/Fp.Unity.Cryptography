#if !HASH_UTILITY_DISABLE_IGNORECASE
#define HASH_UTILITY_IGNORECASE
#endif

#if HASH_UTILITY_THREADSAFE
#define THREADSAFE_BUFFER
#endif

using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

using Fp.Utility.Cryptography.Hashing.Crc32;

using UnityEngine;

namespace Fp.Utility.Cryptography
{
    public static class HashUtility
    {
#if THREADSAFE_BUFFER
        [ThreadStatic]
        private static byte[] _hashingBuffer;
#else
        private static byte[] _hashingBuffer = new byte[128];
#endif

        private static readonly Dictionary<string, uint> KeyHashes;
        
        static HashUtility()
        {
#if HASH_UTILITY_IGNORECASE
            KeyHashes = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
#else
            KeyHashes = new Dictionary<string, uint>(StringComparer.Ordinal);
#endif
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint HashCrc32(string value)
        {
            char[] charArray = value.ToCharArray();
            int byteLen = Encoding.UTF8.GetByteCount(charArray, 0, charArray.Length);
            
#if THREADSAFE_BUFFER
            _hashingBuffer ??= new byte[Mathf.NextPowerOfTwo(byteLen)];
#endif
            
            if (byteLen > _hashingBuffer.Length)
            {
                Array.Resize(ref _hashingBuffer, Mathf.NextPowerOfTwo(byteLen));
            }

            int bytes = Encoding.UTF8.GetBytes(charArray, 0, charArray.Length, _hashingBuffer, 0);
            uint hash = Crc32Algorithm.Compute(_hashingBuffer, 0, bytes);
            return hash;
        }

        public static uint GetHashKeyCached(string key)
        {
            GetHashKeyCached(key, out uint r);
            return r;
        }

        public static void GetHashKeyCached(string key, out uint hash)
        {
            if (KeyHashes.TryGetValue(key, out hash))
            {
                return;
            }

#if HASH_UTILITY_IGNORECASE
            key = key.ToLowerInvariant();
#endif

            hash = HashCrc32(key);
            KeyHashes[key] = hash;
        }
    }
}