// This file is part of the mkcheck project.
// Licensing information can be found in the LICENSE file.
// (C) 2017 Nandor Licker. All rights reserved.

#include <cassert>
#include <cstdlib>
#include <cstring>

#include <memory>
#include <iostream>
#include <set>
#include <string>
#include <vector>
#include <unordered_map>

#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "syscall.h"
#include "trace.h"
#include "util.h"



// -----------------------------------------------------------------------------
class ProcessState final {
public:
  /// Initialises the process state.
  ProcessState(pid_t pid)
    : pid_(pid)
    , entering_(false)
  {
  }

  /// Indicates if we're exiting/exiting the syscall.
  bool IsExiting() const { return !entering_; }

  /// Returns the syscall number.
  int64_t GetSyscall() const { return syscall_; }

  /// Returns the return value.
  int64_t GetReturn() const { return return_; }

  /// Returns a specific argument.
  uint64_t GetArg(size_t idx) const
  {
    assert(idx < kSyscallArgs);
    return args_[idx];
  }

  /// Returns the arguments.
  Args GetArgs() const
  {
    Args args;
    args.PID = pid_;
    args.Return = return_;
    for (size_t i = 0; i < kSyscallArgs; ++i) {
      args.Arg[i] = args_[i];
    }
    return args;
  }

  /// Extracts information from a register set.
  void Read(const struct user_regs_struct *regs)
  {
    if (entering_) {
      return_ = regs->rax;
      entering_ = false;
    } else {
      syscall_ = regs->orig_rax;
      args_[0] = regs->rdi;
      args_[1] = regs->rsi;
      args_[2] = regs->rdx;
      args_[3] = regs->r10;
      args_[4] = regs->r8;
      args_[5] = regs->r9;
      entering_ = true;
    }
  }

  /// Sets the name of the executable.
  void SetExecutable(const std::string &exec)
  {
    exec_ = exec;
  }

  /// Returns the name of the executable.
  std::string GetExecutable() const
  {
    return exec_;
  }

  void SetIgnoreFds(const std::set<int> &fds)
  {
    ignoreFDs_ = fds;
  }

  std::set<int> GetIgnoreFds() const
  {
    return ignoreFDs_;
  }

private:
  /// PID of the traced process.
  pid_t pid_;
  /// Flag to indicate if the syscall is entered/exited.
  bool entering_;
  /// Name of the executable.
  std::string exec_;
  /// Set of file descriptors to ignore.
  std::set<int> ignoreFDs_;
  /// List of arguments.
  uint64_t args_[kSyscallArgs];
  /// Return value.
  int64_t return_;
  /// Syscall number.
  int64_t syscall_;
};


// -----------------------------------------------------------------------------
bool IsExecutable(const fs::path &path)
{
  struct stat st;

  // Check if file exists.
  if (stat(path.string().c_str(), &st) != 0) {
    return false;
  }
  // Ensure it is a file.
  if (!S_ISREG(st.st_mode)) {
    return false;
  }
  // Check if it is user-executable.
  if (!(st.st_mode & S_IXUSR)) {
    return false;
  }
  return true;
}

// -----------------------------------------------------------------------------
std::string FindExecutable(const std::string &exec)
{
  fs::path candidate = fs::absolute(exec);
  if (IsExecutable(candidate)) {
    return candidate.string();
  }

  const char *colon;
  const char *ptr = getenv("PATH");
  do {
    colon = strchr(ptr, ':');

    const fs::path path = std::string(ptr, colon ? colon - ptr : strlen(ptr));
    
    candidate = path / exec;
    if (IsExecutable(candidate)) {
      return candidate.string();
    }
    ptr = colon + 1;
  } while (colon);
  
  throw std::runtime_error("Cannot find executable: " + exec);
}

std::string ParseGmakeJobserverOptions(std::string mkflags)
{
  // Parse --jobserver-auth=X
  // If multiple are present, the last one wins.
  const char *options[] = {
    "--jobserver-auth=",
    "--jobserver-fds=",
  };

  for (const char *option : options) {
    size_t pos = mkflags.rfind(option);
    if (pos != std::string::npos) {
      size_t end = mkflags.find(' ', pos);
      if (end == std::string::npos) {
        end = mkflags.size();
      }
      std::string word = mkflags.substr(pos, end - pos);
      // Return everything after the '='.
      return word.substr(word.find('=') + 1);
    }
  }
  return "";
}

// -----------------------------------------------------------------------------
int RunChild(const std::string &exec, const std::vector<char *> &args)
{
  ptrace(PTRACE_TRACEME);
  raise(SIGSTOP);
  return execvp(exec.c_str(), args.data());
}

// -----------------------------------------------------------------------------
static constexpr int kTraceOptions
  = PTRACE_O_TRACESYSGOOD
  | PTRACE_O_TRACECLONE
  | PTRACE_O_TRACEFORK
  | PTRACE_O_TRACEVFORK
  | PTRACE_O_EXITKILL
  ;

// -----------------------------------------------------------------------------
int RunTracer(const fs::path &output, pid_t root)
{
  // Trace context.
  auto trace = std::make_unique<Trace>();

  // Skip the first signal, which is SIGSTOP.
  int status;
  waitpid(root, &status, 0);
  ptrace(PTRACE_SETOPTIONS, root, nullptr, kTraceOptions);
  trace->SpawnTrace(0, root);

  // Set of tracked processses.
  std::unordered_map<pid_t, std::shared_ptr<ProcessState>> tracked;
  tracked[root] = std::make_shared<ProcessState>(root);
  
  auto GetState = [&tracked](pid_t pid, bool clone = false) {
    auto it = tracked.find(pid);
    if (it == tracked.end()) {
      throw std::runtime_error("Invalid PID: " + std::to_string(pid) + " clone=" + std::to_string(clone));
    }
    return it->second;
  };

  // Processes waiting to be started.
  std::set<pid_t> candidates;

  // Process to wait for - after clone/vfork/exec, the callee is given
  // priority in order to trap and set up the child's data structure.
  // Otherwise, it is -1, stopping the first available child.
  pid_t waitFor = -1;

  // Keep tracking syscalls while any process in the hierarchy is running.
  int restartSig = 0;
  pid_t pid = root;
  while (!tracked.empty()) {
    // Trap a child on the next syscall.
    if (pid > 0) {
      if (ptrace(PTRACE_SYSCALL, pid, 0, restartSig) < 0) {
        throw std::runtime_error("ptrace failed");
      }
    }

    // Wait for a child or any children to stop.
    if ((pid = waitpid(waitFor, &status, __WALL)) < 0) {
      throw std::runtime_error("waitpid failed");
    }
    waitFor = -1;

    // The root process must exit with 0.
    if (WIFEXITED(status) && pid == root) {
      const int code = WEXITSTATUS(status);
      if (code != 0) {
        throw std::runtime_error("non-zero exit " + std::to_string(code)
        );
      }
    }

    // The root process should not exit with a signal.
    if (WIFSIGNALED(status) && pid == root) {
      const int signo = WTERMSIG(status);
      throw std::runtime_error("killed by signal " + std::to_string(signo));
    }

    // Remove the process from the tracked ones on exit.
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      trace->EndTrace(pid);
      tracked.erase(pid);
      pid = -1;
      continue;
    }

    /// Handle signals dispatched to children.
    switch (int sig = WSTOPSIG(status)) {
      case SIGTRAP | 0x80: {
        // By setting PTRACE_O_TRACESYSGOOD, bit 7 of the system call
        // number is set in order to distinguish system call traps
        // from other traps.
        restartSig = 0;
        break;
      }
      case SIGTRAP: {
        // SIGTRAP is sent with an event number in certain scenarios.
        // Simply restart the process with signal number 0.
        const int event = status >> 16;
        switch (event) {
          case PTRACE_EVENT_FORK:
          case PTRACE_EVENT_VFORK:
          case PTRACE_EVENT_CLONE: {
            bool shareVM = false;
            if (event == PTRACE_EVENT_CLONE) {
              shareVM = GetState(pid, true)->GetArg(2) & CLONE_VM;
            }
            
            // Get the ID of the child process.
            pid_t child;
            ptrace(PTRACE_GETEVENTMSG, pid, 0, &child);

            // Set tracing options for the child.
            ptrace(PTRACE_SETOPTIONS, pid, nullptr, kTraceOptions);
            
            // Create an object tracking the process, if one does not exist yet.
            tracked.emplace(child, std::make_shared<ProcessState>(child));
            
            if (shareVM) {
              // Shared the parent's structure with the child thread.
              trace->ShareTrace(pid, child);
            } else {
              // Spawn a new tracking state for the child.
              trace->SpawnTrace(pid, child);
            }

            // Start tracking it.
            candidates.insert(child);
            restartSig = 0;
            break;
          }
          case 0: {
            break;
          }
          default: {
            printf("Unknown event: %d\n", event);
            break;
          }
        }
        restartSig = 0;
        continue;
      }
      case SIGSTOP: {
        auto it = candidates.find(pid);
        if (it != candidates.end()) {
          // The first SIGSTOP is ignored.
          candidates.erase(it);
          restartSig = 0;
        } else {
          restartSig = SIGSTOP;
        }
        continue;
      }
      default: {
        // Deliver other signals to the process.
        restartSig = sig;
        continue;
      }
    }

    // Fetch the state desribing the process.
    std::shared_ptr<ProcessState> state = GetState(pid);

    // Read syscall arguments on entry & the return value on exit.
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    state->Read(&regs);

    // Handle the system call.
    auto sno = state->GetSyscall();
    switch (sno) {
      case SYS_execve: {
        // Execve is special since its arguments can't be read once the
        // process image is replaced, thus the argument is read on entry.
        if (state->IsExiting()) {
          if (state->GetReturn() >= 0) {
            trace->StartTrace(pid, state->GetExecutable(), state->GetIgnoreFds());
          }
        } else {
          // Read envp and check MAKEFLAGS to parse --jobserver-auth to exclude
          // those file descriptors from the trace.
          const char *MAKEFLAGS_ENVS[] = {
            "MAKEFLAGS",
            "CARGO_MAKEFLAGS",
          };

          for (const char *env : MAKEFLAGS_ENVS) {
            std::string makeflags = ReadEnv(pid, state->GetArg(2), env);
            std::string jobserver = ParseGmakeJobserverOptions(makeflags);
            if (!jobserver.empty()) {
              // If "fifo:<FILE>", exclude the file path.
              size_t fifoPos = jobserver.find("fifo:");
              if (fifoPos == 0) {
                std::string path = jobserver.substr(fifoPos + 5);
                trace->Ignore(path);
              } else {
                // Otherwise, parse as "R,W" and exclude the file descriptors.
                std::set<int> fds;
                size_t pos = 0;
                while (pos < jobserver.size()) {
                  size_t end = jobserver.find(',', pos);
                  if (end == std::string::npos) {
                    end = jobserver.size();
                  }
                  int fd = std::stoi(jobserver.substr(pos, end - pos));
                  fds.insert(fd);
                  pos = end + 1;
                }
                state->SetIgnoreFds(fds);
              }
            }
          }

          state->SetExecutable(ReadString(pid, state->GetArg(0)));
        }
        break;
      }
      case SYS_vfork:
      case SYS_fork: 
      case SYS_clone:
      case SYS_clone3: {
        // Try to wait for the exit event of this sycall before any others.
        waitFor = state->IsExiting() ? -1 : pid;
        break;
      }
    }

    // All other system calls are handled on exit.
    if (state->IsExiting()) {
      Handle(trace.get(), sno, state->GetArgs());
    }
  }

  trace->Dump(output);
  return EXIT_SUCCESS;
}

// -----------------------------------------------------------------------------
static struct option kOptions[] =
{
  { "output",  required_argument, 0, 'o' },
};

// -----------------------------------------------------------------------------
int main(int argc, char **argv)
{
  // Parse arguments.
  std::string output;
  std::string exec;
  std::vector<char *> args;
  {
    int c = 0, idx = 0;
    while (c >= 0) {
      switch (c = getopt_long(argc, argv, "o:", kOptions, &idx)) {
        case -1: {
          break;
        }
        case 'o': {
          output = optarg;
          continue;
        }
        default: {
          std::cerr << "Unknown option." << std::endl;
          return EXIT_FAILURE;
        }
      }
    }

    if (output.empty()) {
      std::cerr << "Missing output directory." << std::endl;
      return EXIT_FAILURE;
    }
    if (optind == argc) {
      std::cerr << "Missing executable." << std::endl;
      return EXIT_FAILURE;
    }

    for (int i = optind; i < argc; ++i) {
      args.push_back(argv[i]);
    }
    args.push_back(nullptr);
    exec = FindExecutable(args[0]);
  }

  // Fork & start tracing.
  switch (pid_t pid = fork()) {
    case -1: {
      return EXIT_FAILURE;
    }
    case 0: {
      return RunChild(exec, args);
    }
    default: {
      try {
        return RunTracer(output, pid);
      } catch (const std::exception &ex) {
        std::cerr << "[Exception] " << ex.what() << std::endl;
        return EXIT_FAILURE;
      }
    }
  }

  return EXIT_SUCCESS;
}
