using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
namespace Test
{
    public class MemoryPatch
    {
        const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        static readonly uint[] AllowedProtect = { 0x40, 0x04 }; // PAGE_EXECUTE_READWRITE
        const long MinRegionSize = 0x200000;//0x2800000;
        const long EndScanSize = 0x60000000; // 1.1GB
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(
         IntPtr hProcess,
         IntPtr lpBaseAddress,
         byte[] lpBuffer,
         int dwSize,
         out int lpNumberOfBytesRead);
        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);
        public static void ParseAOB(string aob, out byte[] pattern, out bool[] mask)
        {
            var tokens = aob.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            var list = new List<byte>();
            var maskList = new List<bool>();
            foreach (var token in tokens)
            {
                if (token == "??" || token == "?")
                {
                    list.Add(0);
                    maskList.Add(false);
                }
                else
                {
                    list.Add(Convert.ToByte(token, 16));
                    maskList.Add(true);
                }
            }
            pattern = list.ToArray();
            mask = maskList.ToArray();
        }
        public static int[] BuildBadCharSkip(byte[] pattern, bool[] mask)
        {
            var skip = new int[256];
            int len = pattern.Length;
            for (int i = 0; i < skip.Length; i++) skip[i] = len;
            for (int i = 0; i < len - 1; i++)
            {
                if (mask[i])
                    skip[pattern[i]] = len - i - 1;
                else
                    for (int b = 0; b < 256; b++)
                        skip[b] = Math.Min(skip[b], len - i - 1);
            }
            return skip;
        }
        // Tối ưu hóa: dùng ReadOnlySpan<byte> + unsafe cho tốc độ tối đa
        public static List<int> FindPatternBoyerMooreUnsafe(ReadOnlySpan<byte> buffer, byte[] pattern, bool[] mask)
        {
            var results = new List<int>();
            int[] skip = BuildBadCharSkip(pattern, mask);
            int blen = buffer.Length, plen = pattern.Length;
            int i = 0;
            unsafe
            {
                fixed (byte* bufPtr = buffer)
                fixed (byte* patPtr = pattern)
                {
                    while (i <= blen - plen)
                    {
                        int j = plen - 1;
                        while (j >= 0 && (!mask[j] || bufPtr[i + j] == patPtr[j]))
                            j--;
                        if (j < 0)
                        {
                            results.Add(i);
                            i++; // overlapping match
                        }
                        else
                        {
                            byte b = bufPtr[i + plen - 1];
                            i += skip[b];
                        }
                    }
                }
            }
            return results;
        }
        // SCAN NHIỀU PATTERN CÙNG LÚC
        public async Task<Dictionary<string, List<long>>> AoBScanMultiPatternParallelAsync(
            string processName,
            string[] patterns,
            long? startAddress = null,
            long? endAddress = null,
            int chunkSize = 0x800000,
            int alignment = 2,
            long? excludeRegionStart = null,
            long? excludeRegionEnd = null)
        {
            var proc = Process.GetProcessesByName(processName).FirstOrDefault();
            if (proc == null) return null!;
            IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, proc.Id);
            if (hProc == IntPtr.Zero) return null!;
            // Parse tất cả patterns trước
            var patInfos = patterns.Select(pat =>
            {
                ParseAOB(pat, out var bytes, out var mask);
                return (pattern: pat, bytes, mask);
            }).ToList();
            // --- Region scan ---
            long scanStart = startAddress ?? 0;
            long scanEnd = endAddress ?? 0x7FFFFFFFFFFF;
            var regions = new List<(long baseAddr, long size)>();
            long addr = scanStart;
            MEMORY_BASIC_INFORMATION mbi;
            while (addr < scanEnd &&
                   VirtualQueryEx(hProc, checked((IntPtr)addr), out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0)
            {
                long regionBase = mbi.BaseAddress.ToInt64();
                long regionSize = (long)mbi.RegionSize;
                long regionEnd = regionBase + regionSize;
                if (excludeRegionStart.HasValue && excludeRegionEnd.HasValue)
                {
                    bool isInExcluded = regionEnd > excludeRegionStart.Value && regionBase < excludeRegionEnd.Value;
                    if (isInExcluded)
                    {
                        addr = regionEnd;
                        continue;
                    }
                }
                if (regionEnd > scanStart && regionBase < scanEnd)
                {
                    long validBase = Math.Max(regionBase, scanStart);
                    long validEnd = Math.Min(regionEnd, scanEnd);
                    long validSize = validEnd - validBase;
                    bool validProtect = AllowedProtect.Contains(mbi.Protect);
                    bool committed = mbi.State == 0x1000;
                    bool notGuarded = (mbi.Protect & 0x100) == 0;
                    if (validProtect && committed && notGuarded && validSize >= MinRegionSize)
                    {
                        //string logPath = "log.txt"; // Ghi log tại thư mục hiện tại
                        if (validSize > EndScanSize)
                        {
                            long endStart = validEnd - EndScanSize;
                            endStart = Math.Max(endStart, validBase);
                            regions.Add((endStart, validEnd - endStart));
                            //double sizeMB1 = (endStart - validBase) / (1024.0 * 1024.0);
                            //double sizeMB2 = (validEnd - endStart) / (1024.0 * 1024.0);
                            //string log = $"Region too large, split into:\n" +
                            //$"1. {validBase:X} - {endStart:X} (≈ {sizeMB1:F2} MB)\n" +
                            //$"2. {endStart:X} - {validEnd:X} (≈ {sizeMB2:F2} MB)\n";
                            //File.AppendAllText(logPath, log); // Ghi vào log.txt
                        }
                        else
                        {
                            regions.Add((validBase, validSize));
                            //double sizeMB = validSize / (1024.0 * 1024.0);
                            //string log = $"Region found: {validBase:X} - {validEnd:X} | Size: {validSize:X} bytes (≈ {sizeMB:F2} MB)\n";
                            //File.AppendAllText(logPath, log); // Ghi vào log.txt
                        }
                    }
                }
                addr = regionEnd;
                if (addr < 0 || addr > scanEnd) break;
            }
            // --- Chunk split tiếp tục như cũ ở dưới ---
            // --- Chunk split ---
            var chunks = new List<(long chunkAddr, long chunkLen)>();
            foreach (var (baseAddr, size) in regions)
            {
                for (long offset = 0; offset < size; offset += chunkSize)
                {
                    long chunkAddr = baseAddr + offset;
                    long chunkLen = Math.Min(chunkSize, size - offset);
                    chunks.Add((chunkAddr, chunkLen));
                }
            }
            var pool = ArrayPool<byte>.Shared;
            int maxDegree = Math.Min(Environment.ProcessorCount * 2, 16);
            var resultDict = new ConcurrentDictionary<string, ConcurrentBag<long>>();
            foreach (var p in patterns)
                resultDict.TryAdd(p, new ConcurrentBag<long>());
            await Parallel.ForEachAsync(chunks, new ParallelOptions { MaxDegreeOfParallelism = maxDegree }, async (chunk, _) =>
            {
                byte[] buffer = pool.Rent((int)chunk.chunkLen);
                try
                {
                    int readed = 0;
                    bool ok = ReadProcessMemory(hProc, (IntPtr)chunk.chunkAddr, buffer, (int)chunk.chunkLen, out readed);
                    if (ok)
                    {
                        var span = new ReadOnlySpan<byte>(buffer, 0, readed);
                        foreach (var (pattern, patBytes, mask) in patInfos)
                        {
                            var offsets = FindPatternBoyerMooreUnsafe(span, patBytes, mask);
                            foreach (var o in offsets)
                                resultDict[pattern].Add(chunk.chunkAddr + o);
                        }
                    }
                }
                finally
                {
                    pool.Return(buffer);
                }
                await Task.CompletedTask;
            });
            CloseHandle(hProc);
            // Convert to Dictionary<string, List<long>>
            return resultDict.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.OrderBy(x => x).ToList());
        }
        // PATCH SONG SONG NHIỀU ĐỊA CHỈ
        public void PatchManyParallel(string processName, List<(long addr, byte[] data)> patches, int maxDegree = 8)
        {
            Parallel.ForEach(patches, new ParallelOptions { MaxDegreeOfParallelism = maxDegree }, patch =>
            {
                WriteMemory(processName, patch.addr, patch.data);
            });
        }
        // --- Các hàm còn lại giữ nguyên ---
        public T ReadMemory<T>(string processName, long address) where T : struct
        {
            var proc = Process.GetProcessesByName(processName).FirstOrDefault();
            if (proc == null) throw new Exception("Process not found");
            IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, proc.Id);
            if (hProc == IntPtr.Zero) throw new Exception("Cannot open process");
            int size = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[size];
            unsafe
            {
                fixed (byte* pBuffer = buffer)
                {
                    if (!ReadProcessMemory(hProc, (IntPtr)address, buffer, size, out int _))
                    {
                        CloseHandle(hProc);
                        throw new Exception("ReadProcessMemory failed");
                    }
                }
            }
            CloseHandle(hProc);
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            T value = Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            handle.Free();
            return value;
        }
        public bool WriteMemory<T>(string processName, long address, T value) where T : struct
        {
            var proc = Process.GetProcessesByName(processName).FirstOrDefault();
            if (proc == null) return false;
            IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, proc.Id);
            if (hProc == IntPtr.Zero) return false;
            int size = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[size];
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), false);
            handle.Free();
            bool ok = WriteProcessMemory(hProc, (IntPtr)address, buffer, buffer.Length, out int written);
            CloseHandle(hProc);
            return ok && written == buffer.Length;
        }
        public bool WriteMemory(string processName, long address, byte[] data)
        {
            var proc = Process.GetProcessesByName(processName).FirstOrDefault();
            if (proc == null) return false;
            IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, proc.Id);
            if (hProc == IntPtr.Zero) return false;
            bool ok = WriteProcessMemory(hProc, (IntPtr)address, data, data.Length, out int written);
            CloseHandle(hProc);
            return ok && written == data.Length;
        }
        public static byte[] StringToByteArray(string hex)
        {
            var tokens = hex.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            var bytes = new byte[tokens.Length];
            for (int i = 0; i < tokens.Length; i++)
            {
                bytes[i] = Convert.ToByte(tokens[i], 16);
            }
            return bytes;
        }
        public byte[] ReadMemory(string processName, long address, int length)
        {
            var proc = Process.GetProcessesByName(processName).FirstOrDefault();
            if (proc == null) throw new Exception("Process not found");
            IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, proc.Id);
            if (hProc == IntPtr.Zero) throw new Exception("Cannot open process");
            byte[] buffer = new byte[length];
            unsafe
            {
                fixed (byte* pBuffer = buffer)
                {
                    if (!ReadProcessMemory(hProc, (IntPtr)address, buffer, length, out int _))
                    {
                        CloseHandle(hProc);
                        throw new Exception("ReadProcessMemory failed");
                    }
                }
            }
            CloseHandle(hProc);
            return buffer;
        }
    }
}
