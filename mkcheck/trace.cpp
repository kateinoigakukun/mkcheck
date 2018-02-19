// This file is part of the mkcheck project.
// Licensing information can be found in the LICENSE file.
// (C) 2017 Nandor Licker. All rights reserved.

#include "trace.h"

#include <cassert>
#include <climits>
#include <iostream>
#include <fstream>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>


// -----------------------------------------------------------------------------
Process::Process(
    Trace *trace,
    pid_t pid,
    uint64_t parent,
    uint64_t uid,
    uint64_t image,
    const FDSet &fdSet,
    const fs::path &cwd,
    bool isCOW)
  : trace_(trace)
  , pid_(pid)
  , parent_(parent)
  , uid_(uid)
  , image_(image)
  , cwd_(cwd)
  , isCOW_(isCOW)
{
  for (const auto &fd : fdSet) {
    files_.emplace(fd.Fd, fd);
  }
}

// -----------------------------------------------------------------------------
Process::~Process()
{
  if (isCOW_) {
    return;
  }

  std::ofstream os((trace_->GetOutput() / std::to_string(uid_)).string());
  os << uid_ << " " << parent_ << " " << image_ << std::endl;

  for (const auto output : outputs_) {
    os << output << " ";
  }
  os << std::endl;

  for (const auto input : inputs_) {
    if (outputs_.find(input) == outputs_.end()) {
      os << input << " ";
    }
  }
  os << std::endl;
}

// -----------------------------------------------------------------------------
fs::path Process::Normalise(const fs::path &path)
{
  return Normalise(AT_FDCWD, path);
}

// -----------------------------------------------------------------------------
fs::path Process::Normalise(int fd, const fs::path &path)
{
  boost::system::error_code ec;

  // Get rid of the relative path.
  fs::path fullPath;
  if (path.is_relative()) {
    if (fd == AT_FDCWD) {
      fullPath = (cwd_ / path).normalize();
    } else {
      throw std::runtime_error("Not implemented: realpath");
    }
  } else {
    fullPath = path;
  }

  // If the file exists, return the canonical path.
  const fs::path canonical = fs::canonical(fullPath, ec);
  if (!ec) {
    return canonical;
  }

  // If the file was deleted, try to canonicalise the parent.
  const fs::path parent = fullPath.parent_path();
  const fs::path file = fullPath.filename();

  const fs::path canonicalParent = fs::canonical(parent, ec);
  if (!ec) {
    return canonicalParent / file;
  }

  std::cerr << fullPath << "\n";
  return fullPath;
}

// -----------------------------------------------------------------------------
void Process::AddInput(const fs::path &path)
{
  inputs_.insert(trace_->Find(path));
}

// -----------------------------------------------------------------------------
void Process::AddOutput(const fs::path &path)
{
  outputs_.insert(trace_->Find(path));
  AddDestination(path);
  trace_->Create(path);
}

// -----------------------------------------------------------------------------
void Process::AddDestination(const fs::path &path)
{
  uint64_t parent = trace_->Find(path.parent_path());
  if (outputs_.find(parent) == outputs_.end()) {
    inputs_.insert(parent);
  }
}

// -----------------------------------------------------------------------------
void Process::Remove(const fs::path &path)
{
  trace_->Unlink(Normalise(path));
}

// -----------------------------------------------------------------------------
void Process::Rename(const fs::path &from, const fs::path &to)
{
  trace_->Unlink(from);
  trace_->AddDependency(from, to);
  AddOutput(to);
}

// -----------------------------------------------------------------------------
void Process::Symlink(const fs::path &target, const fs::path &linkpath)
{
  trace_->AddDependency(target, linkpath);
  trace_->Create(linkpath);
  AddOutput(linkpath);
}

// -----------------------------------------------------------------------------
void Process::MapFd(int fd, const fs::path &path)
{
  FDInfo info(fd, path, false);

  auto it = files_.find(fd);
  if (it == files_.end()) {
    files_.emplace(fd, info);
  } else {
    it->second = info;
  }
}

// -----------------------------------------------------------------------------
fs::path Process::GetFd(int fd)
{
  auto it = files_.find(fd);
  if (it == files_.end()) {
    throw std::runtime_error(
        "Unknown file descriptor: " + std::to_string(fd)
    );
  }
  return it->second.Path;
}

// -----------------------------------------------------------------------------
void Process::DupFd(int from, int to)
{
  auto it = files_.find(from);
  if (it == files_.end()) {
    throw std::runtime_error(
        "Unknown file descriptor: " + std::to_string(from)
    );
  }

  FDInfo info(to, it->second.Path, false);

  auto jt = files_.find(to);
  if (jt == files_.end()) {
    files_.emplace(to, info);
  } else {
    jt->second = info;
  }
}

// -----------------------------------------------------------------------------
void Process::SetCloseExec(int fd)
{
  auto it = files_.find(fd);
  if (it == files_.end()) {
    throw std::runtime_error(
        "Unknown file descriptor: " + std::to_string(fd)
    );
  }

  it->second.CloseExec = true;
}

// -----------------------------------------------------------------------------
void Process::ClearCloseExec(int fd)
{
  auto it = files_.find(fd);
  if (it == files_.end()) {
    throw std::runtime_error(
        "Unknown file descriptor: " + std::to_string(fd)
    );
  }

  it->second.CloseExec = false;
}

// -----------------------------------------------------------------------------
FDSet Process::GetAllFDs()
{
  FDSet fdSet;
  for (const auto &file : files_) {
    fdSet.emplace_back(file.second);
  }
  return fdSet;
}

// -----------------------------------------------------------------------------
FDSet Process::GetInheritedFDs()
{
  FDSet fdSet;
  for (auto &file : files_) {
    const auto info = file.second;
    if (!info.CloseExec) {
      fdSet.emplace_back(info);
    }
  }
  return fdSet;
}

// -----------------------------------------------------------------------------
Trace::Trace(const fs::path &output)
  : output_(fs::absolute(output).normalize())
  , nextUID_(1)
  , nextFID_(1)
{
  if (fs::exists(output)) {
    fs::remove_all(output);
  }
  if (!fs::create_directories(output)) {
    throw std::runtime_error("Cannot create directory.");
  }
}

// -----------------------------------------------------------------------------
Trace::~Trace()
{
  // Save the list of files.
  {
    std::ofstream os((output_ / "files").string());
    os << "[";
    for (auto it = fileInfos_.begin(); it != fileInfos_.end();) {
      const auto &info = it->second;
      os << "{";
      os << "\"id\": " << it->first << ",";
      os << "\"name\": \"" << info.Name << "\"";
      if (info.Deleted) {
        os << ",\"deleted\": true";
      }
      if (!info.Deps.empty()) {
        os << ",\"deps\": [";
        for (auto jt = info.Deps.begin(); jt != info.Deps.end();) {
          os << *jt;
          if (++jt != info.Deps.end()) {
            os << ",";
          }
        }
        os << "]";
      }
      os << "}";
      if (++it != fileInfos_.end()) {
        os << ",\n";
      }
    }
    os << "]";
  }

  // Save the list of processes.
  {
    std::vector<uint64_t> procs;
    for (const auto &proc : procs_) {
      if (!proc.second->IsCOW()) {
        procs.push_back(proc.second->GetUID());
      }
    }

    std::ofstream os((output_ / "procs").string());
    os << "[";
    for (auto it = procs.begin(); it != procs.end();) {
      os << *it;
      if (++it != procs.end()) {
        os << ",";
      }
    }
    os << "]";
  }
}

// -----------------------------------------------------------------------------
void Trace::SpawnTrace(pid_t parent, pid_t pid)
{
  // Find the working directory.
  fs::path cwd;
  uint64_t parentUID;
  uint64_t image;
  FDSet fdSet;
  {
    auto it = procs_.find(parent);
    if (it == procs_.end()) {
      char buffer[PATH_MAX];
      getcwd(buffer, PATH_MAX);
      cwd = buffer;
      image = 0;
      parentUID = 0;

      fdSet.emplace_back(0, "/dev/stdin", false);
      fdSet.emplace_back(1, "/dev/stdout", false);
      fdSet.emplace_back(2, "/dev/stderr", false);
    } else {
      auto proc = it->second;
      cwd = proc->GetCwd();
      image = proc->GetImage();
      parentUID = proc->GetUID();
      fdSet = proc->GetAllFDs();
    }
  }

  // Create the COW trace.
  procs_.emplace(pid, std::make_shared<Process>(
      this,
      pid,
      parentUID,
      nextUID_++,
      image,
      fdSet,
      cwd,
      true
  ));
}

// -----------------------------------------------------------------------------
void Trace::StartTrace(pid_t pid, const fs::path &image)
{
  // Find the previous copy - it must exist.
  auto it = procs_.find(pid);
  assert(it != procs_.end());
  auto proc = it->second;

  // Replace with a non-COW trace which has a new image.
  it->second = std::make_shared<Process>(
      this,
      pid,
      proc->GetParent(),
      nextUID_++,
      Find(image),
      proc->GetInheritedFDs(),
      proc->GetCwd(),
      false
  );
}

// -----------------------------------------------------------------------------
void Trace::EndTrace(pid_t pid)
{
}

// -----------------------------------------------------------------------------
Process *Trace::GetTrace(pid_t pid)
{
  auto it = procs_.find(pid);
  assert(it != procs_.end());
  return it->second.get();
}

// -----------------------------------------------------------------------------
void Trace::Unlink(const fs::path &path)
{
  auto fileID = Find(path);
  auto &info = fileInfos_.find(fileID)->second;
  info.Deleted = true;
}

// -----------------------------------------------------------------------------
uint64_t Trace::Find(const fs::path &path)
{
  const std::string name = path.string();
  auto it = fileIDs_.find(name);
  if (it == fileIDs_.end()) {
    uint64_t id = nextFID_++;
    fileIDs_.emplace(name, id);
    fileInfos_.emplace(id, name);
    return id;
  } else {
    return it->second;
  }
}

// -----------------------------------------------------------------------------
void Trace::Create(const fs::path &path)
{
  const std::string name = path.string();
  auto it = fileIDs_.find(name);
  if (it == fileIDs_.end()) {
    throw std::runtime_error("Unknown file: " + path.string());
  }
  fileInfos_.find(it->second)->second.Deleted = false;
}

// -----------------------------------------------------------------------------
std::string Trace::GetFileName(uint64_t fid) const
{
  auto it = fileInfos_.find(fid);
  assert(it != fileInfos_.end());
  return it->second.Name;
}

// -----------------------------------------------------------------------------
void Trace::AddDependency(const fs::path &src, const fs::path &dst)
{
  const auto sID = Find(src);
  const auto dID = Find(dst);

  auto &info = fileInfos_.find(dID)->second;
  info.Deps.push_back(sID);
}
