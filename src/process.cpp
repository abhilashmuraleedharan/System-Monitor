#include <unistd.h>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "process.h"

using std::string;
using std::to_string;
using std::vector;

// Constructor
Process::Process(int pid, string user, string command) : pid_(pid), user_(user), command_(command) {}

// Return this process's ID
int Process::Pid() { return pid_; }

// Return this process's CPU utilization
float Process::CpuUtilization() const { 
   long total_time = LinuxParser::ActiveJiffies(pid_);
   long seconds = LinuxParser::UpTime() - this->UpTime();
   return ((total_time/sysconf(_SC_CLK_TCK))/(seconds * 1.0));
}

// Return the command that generated this process
string Process::Command() { return command_; }

// Return this process's memory utilization
string Process::Ram() { 
   return LinuxParser::Ram(pid_); 
}

// Return the user (name) that generated this process
string Process::User() { return user_; }

// Return the age of this process (in seconds)
long int Process::UpTime() const { 
   return LinuxParser::UpTime(pid_); 
}

// Overload the "greater than" comparison operator for Process objects
bool Process::operator>(const Process & a) const { 
   float lhs_cpu = this->CpuUtilization();
   float rhs_cpu = a.CpuUtilization();
   return lhs_cpu > rhs_cpu;
}