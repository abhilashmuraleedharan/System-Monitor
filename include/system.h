#ifndef SYSTEM_H
#define SYSTEM_H

#include <string>
#include <vector>

#include "linux_parser.h"
#include "process.h"
#include "processor.h"

class System {
 public:
  System(); 
  Processor& Cpu();
  std::vector<Process>& Processes();  
  double MemoryUtilization() const;          
  long UpTime() const;                      
  int TotalProcesses() const;               
  int RunningProcesses() const;             
  std::string Kernel() const;               
  std::string OperatingSystem() const;      

 private:
  Processor cpu_ = {};
  std::vector<Process> processes_ = {};
  std::string kernel_;
  std::string system_name_;
};

#endif