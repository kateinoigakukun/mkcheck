// This file is part of the mkcheck project.
// Licensing information can be found in the LICENSE file.
// (C) 2017 Nandor Licker. All rights reserved.

#include "util.h"

#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>

#include <sys/uio.h>


// -----------------------------------------------------------------------------
constexpr size_t kPageSize = 4096;

// -----------------------------------------------------------------------------
ssize_t ReadBuffer(pid_t pid, void *dst, uint64_t src, size_t len)
{
  const struct iovec local =
  {
    .iov_base = dst,
    .iov_len = len
  };

  const struct iovec remote =
  {
    .iov_base = reinterpret_cast<void *>(src),
    .iov_len = len
  };

  return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

// -----------------------------------------------------------------------------
std::string ReadString(pid_t pid, uint64_t addr)
{
  return ReadString(pid, addr, std::numeric_limits<size_t>::max());
}

// -----------------------------------------------------------------------------
std::string ReadString(pid_t pid, uint64_t addr, size_t len)
{
  std::string result;
  char buffer[kPageSize];
  uint64_t read = 0;

  for (size_t i = 0; i < len; ++i) {
    const uint64_t end = (addr + kPageSize) & (kPageSize - 1);
    const uint64_t len = kPageSize - end;

    ssize_t count = ReadBuffer(pid, buffer, addr, len);
    if (count < 0) {
      throw std::runtime_error(
          "Cannot read from child memory (errno = " +
          std::to_string(errno) +
          ")"
      );
    }

    for (size_t i = 0; i < count; ++i) {
      if (buffer[i] == '\0') {
        result.append(buffer, i);
        return result;
      }
    }

    result.append(buffer, count);
    addr += count;
  }

  return result;
}

// -----------------------------------------------------------------------------
std::string ReadEnv(pid_t pid, uint64_t envp, std::string key)
{
  // envp is an array of pointers to strings, conventionally of the
  // form key=value, which are passed as the environment of the new
  // program.  The envp array must be terminated by a null pointer.

  while (true) {
    uint64_t entryPtr;
    ssize_t read = ReadBuffer(pid, &entryPtr, envp, sizeof(uint64_t));
    if (entryPtr == 0) {
      return "";
    }

    std::string entry = ReadString(pid, entryPtr);
    size_t eq = entry.find("=");
    if (eq == std::string::npos) {
      continue;
    }
    if (entry.substr(0, eq) == key) {
      return entry.substr(eq + 1);
    }
    envp += sizeof(uint64_t);
  }
}