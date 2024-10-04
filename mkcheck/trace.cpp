// This file is part of the mkcheck project.
// Licensing information can be found in the LICENSE file.
// (C) 2017 Nandor Licker. All rights reserved.

#include <fstream>
#include <climits>

#include "proc.h"
#include "trace.h"



// -----------------------------------------------------------------------------
Trace::Trace()
  : nextUID_(1)
  , nextFID_(1)
{
}

// -----------------------------------------------------------------------------
Trace::~Trace()
{
}

// -----------------------------------------------------------------------------
void Trace::Dump(const fs::path &output)
{
  std::ofstream os(output.string());

  // Save the list of files.
  os << "{" << std::endl;
  {
    os << "\"files\": [" << std::endl;
    for (auto it = fileInfos_.begin(); it != fileInfos_.end();) {
      const auto &info = it->second;
      os << "{";
      os << "\"id\": " << it->first << ",";
      os << "\"name\": \"" << info.Name << "\"";
      if (info.Deleted) {
        os << ",\"deleted\": true";
      }
      if (info.Exists) {
        os << ",\"exists\": true";
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
        os << "," << std::endl;
      }
    }
    os << "]," << std::endl;
  }

  // Save the list of processes.
  {
    os << "\"procs\": [" << std::endl;
    for (auto it = procs_.begin(); it != procs_.end();) {
      it->second->Dump(os);
      if (++it != procs_.end()) {
        os << ",";
      }
    }
    os << "]" << std::endl;
  }
  os << "}" << std::endl;
}

// -----------------------------------------------------------------------------
void Trace::ShareTrace(pid_t parent, pid_t pid)
{
  auto it = procs_.find(parent);
  if (it == procs_.end()) {
    throw std::runtime_error("Process " + std::to_string(parent) + " missing");
  }
  procs_.emplace(pid, it->second);
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
      Find(proc->Normalise(image)),
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
  info.Exists = false;
}

// -----------------------------------------------------------------------------
uint64_t Trace::Find(const fs::path &path)
{
  if (!path.is_absolute()) {
    throw std::runtime_error("Path not absolute: " + path.string());
  }

  const std::string name = path.string();
  auto it = fileIDs_.find(name);
  if (it == fileIDs_.end()) {
    uint64_t id = nextFID_++;
    fileIDs_.emplace(name, id);
    fs::file_status status = fs::symlink_status(path);
    bool exists = fs::exists(status);
    fileInfos_.emplace(id, FileInfo(name, exists));
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

  FileInfo &info = fileInfos_.find(it->second)->second;
  info.Deleted = false;
  info.Exists = true;
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
  info.Deps.insert(sID);
}
