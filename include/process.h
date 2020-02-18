#ifndef PROCESS_H
#define PROCESS_H

#include <string>
/*
 * Basic class for Process representation
 */
class Process {
 public:
  Process(int pid, std::string user, std::string command); // Constructor
  int Pid();                               
  std::string User();                      
  std::string Command();                   
  float CpuUtilization();                  // TODO: See src/process.cpp
  std::string Ram();                       
  long int UpTime();                       
  bool operator<(Process const& a) const;

 private:
  int pid_;
  std::string user_;
  std::string command_;
};

#endif