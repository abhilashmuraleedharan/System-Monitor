#ifndef PROCESS_H
#define PROCESS_H

#include <string>
#include "linux_parser.h"

/*
 * Basic class for Process representation
 */
class Process {
 public:
  Process(int pid, std::string user, std::string command); // Constructor
  int Pid() const;                               
  std::string User() const;                      
  std::string Command() const;                   
  double CpuUtilization() const;
  std::string Ram() const;                       
  long UpTime() const;                      
  bool operator<(const Process & a) const;

 private:
  int pid_;
  std::string user_;
  std::string command_;
};

#endif