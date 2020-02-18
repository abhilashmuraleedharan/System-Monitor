#include <unistd.h>
#include <cstddef>
#include <set>
#include <string>
#include <vector>

#include "linux_parser.h"
#include "process.h"
#include "processor.h"
#include "system.h"

using std::set;
using std::size_t;
using std::string;
using std::vector;

// System object's Constructor
System::System() {
   kernel_ = LinuxParser::Kernel();
   system_name_ = LinuxParser::OperatingSystem();
}

// TODO: Return the system's CPU
Processor& System::Cpu() { return cpu_; }

// Return a container composed of the system's processes
vector<Process>& System::Processes() { 
   vector<int> pids = LinuxParser::Pids();
   string command, user;
   for(int pid : pids) {
      command = LinuxParser::Command(pid);
      user = LinuxParser::User(pid);
      processes_.push_back(Process(pid, user, command));
   } 
   return processes_;
}

// Return the system's kernel identifier (string)
std::string System::Kernel() { return kernel_; }

// Return the system's memory utilization
float System::MemoryUtilization() { 
   return LinuxParser::MemoryUtilization(); 
}

// Return the operating system name
std::string System::OperatingSystem() { return system_name_; }

// Return the number of processes actively running on the system
int System::RunningProcesses() { 
   return LinuxParser::RunningProcesses(); 
}

// Return the total number of processes on the system
int System::TotalProcesses() { 
   return LinuxParser::TotalProcesses(); 
}

// Return the number of seconds since the system started running
long int System::UpTime() { 
   return LinuxParser::UpTime();
}