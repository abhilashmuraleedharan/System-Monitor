#include <unistd.h>
#include <string>
#include <vector>
#include "system.h"

using std::string;
using std::vector;
using std::sort;

// System object's Constructor
System::System() {
   kernel_ = LinuxParser::Kernel();
   system_name_ = LinuxParser::OperatingSystem();
}

// Return the system's CPU
Processor& System::Cpu() { return cpu_; }

// Return a container composed of the system's processes
vector<Process>& System::Processes() { 
   vector<int> pids = LinuxParser::Pids();
   string command{};
   string user{};
   processes_.clear();
   for(int pid : pids) {
      command = LinuxParser::Command(pid);
      user = LinuxParser::User(pid);
      processes_.emplace_back(pid, user, command);
   } 
   sort(processes_.begin(), processes_.end());
   return processes_;
}

// Return the system's kernel identifier (string)
std::string System::Kernel() const { return kernel_; }

// Return the system's memory utilization
double System::MemoryUtilization() const { 
   return LinuxParser::MemoryUtilization(); 
}

// Return the operating system name
std::string System::OperatingSystem() const { return system_name_; }

// Return the number of processes actively running on the system
int System::RunningProcesses() const { 
   return LinuxParser::RunningProcesses(); 
}

// Return the total number of processes on the system
int System::TotalProcesses() const { 
   return LinuxParser::TotalProcesses(); 
}

// Return the number of seconds since the system started running
long System::UpTime() const { 
   return LinuxParser::UpTime();
}