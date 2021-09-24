using System;
using System.IO;

namespace Fp.Utility.Cryptography.Hashing
{
    public class HashXX
    {
        private const uint Prime321 = 2654435761U;
        private const uint Prime322 = 2246822519U;
        private const uint Prime323 = 3266489917U;
        private const uint Prime324 = 668265263U;
        private const uint Prime325 = 374761393U;

        protected XxhState State;

        public static uint CalculateHash(byte[] buf, int len = -1, uint seed = 0)
        {
            uint h32;
            var index = 0;
            if (len == -1)
            {
                len = buf.Length;
            }

            if (len >= 16)
            {
                int limit = len - 16;
                uint v1 = seed + Prime321 + Prime322;
                uint v2 = seed + Prime322;
                uint v3 = seed + 0;
                uint v4 = seed - Prime321;

                do
                {
                    v1 = CalcSubHash(v1, buf, index);
                    index += 4;
                    v2 = CalcSubHash(v2, buf, index);
                    index += 4;
                    v3 = CalcSubHash(v3, buf, index);
                    index += 4;
                    v4 = CalcSubHash(v4, buf, index);
                    index += 4;
                }
                while (index <= limit);

                h32 = RotateLeft(v1, 1) + RotateLeft(v2, 7) + RotateLeft(v3, 12) + RotateLeft(v4, 18);
            }
            else
            {
                h32 = seed + Prime325;
            }

            h32 += (uint)len;

            while (index <= len - 4)
            {
                h32 += BitConverter.ToUInt32(buf, index) * Prime323;
                h32 = RotateLeft(h32, 17) * Prime324;
                index += 4;
            }

            while (index < len)
            {
                h32 += buf[index] * Prime325;
                h32 = RotateLeft(h32, 11) * Prime321;
                index++;
            }

            h32 ^= h32 >> 15;
            h32 *= Prime322;
            h32 ^= h32 >> 13;
            h32 *= Prime323;
            h32 ^= h32 >> 16;

            return h32;
        }

        public static uint CalculateHash(Stream stream, long len = -1, uint seed = 0)
        {
            uint h32;
            var index = 0;

            if (!stream.CanRead || !stream.CanSeek)
            {
                throw new InvalidOperationException("Stream has to be seekable and readable");
            }

            if (len == -1)
            {
                len = stream.Length;
            }

            long streamPosition = stream.Position;
            stream.Seek(0, SeekOrigin.Begin);

            var buffer = new byte[16];
            if (len >= 16)
            {
                long limit = len - 16;
                uint v1 = seed + Prime321 + Prime322;
                uint v2 = seed + Prime322;
                uint v3 = seed + 0;
                uint v4 = seed - Prime321;

                do
                {
                    var loopIndex = 0;
                    stream.Read(buffer, 0, buffer.Length);

                    v1 = CalcSubHash(v1, buffer, loopIndex);
                    loopIndex += 4;
                    v2 = CalcSubHash(v2, buffer, loopIndex);
                    loopIndex += 4;
                    v3 = CalcSubHash(v3, buffer, loopIndex);
                    loopIndex += 4;
                    v4 = CalcSubHash(v4, buffer, loopIndex);
                    loopIndex += 4;

                    index += loopIndex;
                }
                while (index <= limit);

                h32 = RotateLeft(v1, 1) + RotateLeft(v2, 7) + RotateLeft(v3, 12) + RotateLeft(v4, 18);
            }
            else
            {
                h32 = seed + Prime325;
            }

            h32 += (uint)len;

            buffer = new byte[4];
            while (index <= len - 4)
            {
                stream.Read(buffer, 0, buffer.Length);
                h32 += BitConverter.ToUInt32(buffer, 0) * Prime323;
                h32 = RotateLeft(h32, 17) * Prime324;
                index += 4;
            }

            buffer = new byte[1];
            while (index < len)
            {
                stream.Read(buffer, 0, buffer.Length);
                h32 += buffer[0] * Prime325;
                h32 = RotateLeft(h32, 11) * Prime321;
                index++;
            }

            stream.Seek(streamPosition, SeekOrigin.Begin);

            h32 ^= h32 >> 15;
            h32 *= Prime322;
            h32 ^= h32 >> 13;
            h32 *= Prime323;
            h32 ^= h32 >> 16;

            return h32;
        }

        public void Init(uint seed = 0)
        {
            State.Seed = seed;
            State.V1 = seed + Prime321 + Prime322;
            State.V2 = seed + Prime322;
            State.V3 = seed + 0;
            State.V4 = seed - Prime321;
            State.TotalLen = 0;
            State.MemSize = 0;
            State.Memory = new byte[16];
        }

        public bool Update(byte[] input, int len)
        {
            var index = 0;

            State.TotalLen += (uint)len;

            if (State.MemSize + len < 16)
            {
                Array.Copy(input, 0, State.Memory, State.MemSize, len);
                State.MemSize += len;

                return true;
            }

            if (State.MemSize > 0)
            {
                Array.Copy(input, 0, State.Memory, State.MemSize, 16 - State.MemSize);

                State.V1 = CalcSubHash(State.V1, State.Memory, index);
                index += 4;
                State.V2 = CalcSubHash(State.V2, State.Memory, index);
                index += 4;
                State.V3 = CalcSubHash(State.V3, State.Memory, index);
                index += 4;
                State.V4 = CalcSubHash(State.V4, State.Memory, index);
                index += 4;

                index = 0;
                State.MemSize = 0;
            }

            if (index <= len - 16)
            {
                int limit = len - 16;
                uint v1 = State.V1;
                uint v2 = State.V2;
                uint v3 = State.V3;
                uint v4 = State.V4;

                do
                {
                    v1 = CalcSubHash(v1, input, index);
                    index += 4;
                    v2 = CalcSubHash(v2, input, index);
                    index += 4;
                    v3 = CalcSubHash(v3, input, index);
                    index += 4;
                    v4 = CalcSubHash(v4, input, index);
                    index += 4;
                }
                while (index <= limit);

                State.V1 = v1;
                State.V2 = v2;
                State.V3 = v3;
                State.V4 = v4;
            }

            if (index >= len)
            {
                return true;
            }

            Array.Copy(input, index, State.Memory, 0, len - index);
            State.MemSize = len - index;

            return true;
        }

        public uint Digest()
        {
            uint h32;
            var index = 0;
            if (State.TotalLen >= 16)
            {
                h32 = RotateLeft(State.V1, 1) + RotateLeft(State.V2, 7) + RotateLeft(State.V3, 12) + RotateLeft(State.V4, 18);
            }
            else
            {
                h32 = State.Seed + Prime325;
            }

            h32 += (uint)State.TotalLen;

            while (index <= State.MemSize - 4)
            {
                h32 += BitConverter.ToUInt32(State.Memory, index) * Prime323;
                h32 = RotateLeft(h32, 17) * Prime324;
                index += 4;
            }

            while (index < State.MemSize)
            {
                h32 += State.Memory[index] * Prime325;
                h32 = RotateLeft(h32, 11) * Prime321;
                index++;
            }

            h32 ^= h32 >> 15;
            h32 *= Prime322;
            h32 ^= h32 >> 13;
            h32 *= Prime323;
            h32 ^= h32 >> 16;

            return h32;
        }

        private static uint CalcSubHash(uint value, byte[] buf, int index)
        {
            uint readValue = BitConverter.ToUInt32(buf, index);
            value += readValue * Prime322;
            value = RotateLeft(value, 13);
            value *= Prime321;
            return value;
        }

        private static uint RotateLeft(uint value, int count)
        {
            return (value << count) | (value >> (32 - count));
        }

        public struct XxhState
        {
            public ulong TotalLen;
            public uint Seed;
            public uint V1;
            public uint V2;
            public uint V3;
            public uint V4;
            public int MemSize;
            public byte[] Memory;
        }
    }
}
