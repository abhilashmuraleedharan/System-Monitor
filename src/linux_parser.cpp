#include <dirent.h>
#include <unistd.h>
#include <string>
#include <sstream>
#include <vector>

#include "linux_parser.h"

using std::stof;
using std::stoi;
using std::stol;
using std::string;
using std::to_string;
using std::vector;

string LinuxParser::OperatingSystem() {
  string line{};
  string key{};
  string value{};
  std::ifstream filestream(kOSPath);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ' ', '_');
      std::replace(line.begin(), line.end(), '=', ' ');
      std::replace(line.begin(), line.end(), '"', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "PRETTY_NAME") {
          std::replace(value.begin(), value.end(), '_', ' ');
          return value;
        }
      }
    }
  }
  return value;
}

string LinuxParser::Kernel() {
  string os, version, kernel;
  string line;
  std::ifstream stream(kProcDirectory + kVersionFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> os >> version >> kernel;
  }
  return kernel;
}

// BONUS: Update this to use std::filesystem
vector<int> LinuxParser::Pids() {
  vector<int> pids;
  DIR* directory = opendir(kProcDirectory.c_str());
  struct dirent* file;
  while ((file = readdir(directory)) != nullptr) {
    // Is this a directory?
    if (file->d_type == DT_DIR) {
      // Is every character of the name a digit?
      string filename(file->d_name);
      if (std::all_of(filename.begin(), filename.end(), isdigit)) {
        int pid = stoi(filename);
        pids.push_back(pid);
      }
    }
  }
  closedir(directory);
  return pids;
}

// Read and return the system memory utilization
float LinuxParser::MemoryUtilization() { 
  float mem_total, mem_free, total_used_mem, buffers, cached;
  float s_reclaimable, shmem, cached_mem, actual_used_mem;
  /*
   * Extract memory usage details from /proc/meminfo 
   */
  string line, key, value;
  int counter = 0;
  std::ifstream filestream(kProcDirectory + kMeminfoFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "MemTotal:") { mem_total = stof(value); counter++; }
        else if (key == "MemFree:") { mem_free = stof(value); counter++; }
        else if (key == "Buffers:") { buffers = stof(value); counter++; }
        else if (key == "Cached:") { cached = stof(value); counter++; }
        else if (key == "SReclaimable:") { s_reclaimable = stof(value); counter++; }
        else if (key == "Shmem:") { shmem = stof(value); counter++; }
      }
      if (counter == 6) { break; } // Check and exit while loop if all details are obtained
    }
  }
  total_used_mem = mem_total - mem_free;
  cached_mem = cached + s_reclaimable - shmem;
  actual_used_mem = total_used_mem - (buffers + cached_mem);
  return actual_used_mem/(mem_total * 1.0); 
}

// Read and return the system uptime
long LinuxParser::UpTime() {
  string up_time, idle_time;
  string line;
  std::ifstream stream(kProcDirectory + kUptimeFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> up_time >> idle_time;
  }
  return stol(up_time);
}

// Read and return the number of jiffies for the system
long LinuxParser::Jiffies() {
  long user, nice, system, irq, softirq, steal;
  user = stol(LinuxParser::cpu_utilization[CPUStates::kUser_]);
  nice = stol(LinuxParser::cpu_utilization[CPUStates::kNice_]);
  system = stol(LinuxParser::cpu_utilization[CPUStates::kSystem_]);
  irq = stol(LinuxParser::cpu_utilization[CPUStates::kIRQ_]);
  softirq = stol(LinuxParser::cpu_utilization[CPUStates::kSoftIRQ_]);
  steal = stol(LinuxParser::cpu_utilization[CPUStates::kSteal_]);
  return user + nice + system + irq + softirq + steal + LinuxParser::idle_jiffies;
}

// Read and return the number of active jiffies for a PID
long LinuxParser::ActiveJiffies(int pid) {
  string line{};
  string token{};
  long utime, stime, cutime, cstime;
  std::ifstream filestream(kProcDirectory + "/" + to_string(pid) + kStatFilename);
  if (filestream.is_open()) {
    std::getline(filestream, line);
    std::istringstream stream(line);
    // Skip till utime token
    for (int i=0; i<14; i++) { stream >> token; }
    utime = stol(token);
    stream >> token;
    stime = stol(token);
    stream >> token;
    cutime = stol(token);
    stream >> token;
    cstime = stol(token);
    return utime + stime + cutime + cstime;
  }
  return 0;
}

// Read and return the number of active jiffies for the system
long LinuxParser::ActiveJiffies() {
  return LinuxParser::jiffies - LinuxParser::idle_jiffies;
}

// Read and return the number of idle jiffies for the system
long LinuxParser::IdleJiffies() { 
  long idle = stol(LinuxParser::cpu_utilization[CPUStates::kIdle_]);
  long iowait = stol(LinuxParser::cpu_utilization[CPUStates::kIOwait_]);
  return idle + iowait; 
}

// Read and return CPU utilization
vector<string> LinuxParser::CpuUtilization() {
  string line{};
  string token{};
  vector<string> tokens{}; 
  std::ifstream filestream(kProcDirectory + kStatFilename);
  if (filestream.is_open()) {
    int i=0;
    std::getline(filestream, line);
    std::istringstream stream(line);
    while(stream >> token) {
      if (i==0) { i++; } // Skip the first token
      else { tokens.push_back(token); }
    }
  }
  return tokens;
}

// Update CPU Utilization
void LinuxParser::UpdateCpuUtilization() {
  LinuxParser::cpu_utilization = LinuxParser::CpuUtilization();
  LinuxParser::idle_jiffies = LinuxParser::IdleJiffies();
  LinuxParser::jiffies = LinuxParser::Jiffies();
  LinuxParser::active_jiffies = LinuxParser::ActiveJiffies();
}

// Read and return the total number of processes
int LinuxParser::TotalProcesses() {
  return LinuxParser::ReadProcStatFile("processes");
}

// Read and return the number of running processes
int LinuxParser::RunningProcesses() {
  return LinuxParser::ReadProcStatFile("procs_running");
}

// Read and return the command associated with a process
string LinuxParser::Command(int pid) {
  string command{};
  std::ifstream stream(kProcDirectory + "/" + to_string(pid) + kCmdlineFilename);
  if (stream.is_open()) {
    std::getline(stream, command);
  }
  return command;
}

// Read and return the memory used by a process
string LinuxParser::Ram(int pid) { 
  int ram = LinuxParser::ReadProcPidStatusFile(pid, "VmSize:");
  return to_string(ram/1024.0); // To convert from KB to MB
}

// Read and return the user ID associated with a process
string LinuxParser::Uid(int pid) { 
  return to_string(ReadProcPidStatusFile(pid, "Uid:"));
}

// Read and return the user associated with a process
string LinuxParser::User(int pid) { 
  string uid = LinuxParser::Uid(pid);
  string user{}; 
  string passwd, userid, line;
  std::ifstream filestream(kPasswordPath);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ':', ' ');
      std::istringstream linestream(line);
      while (linestream >> user >> passwd >> userid) {
        if (userid == uid) { return user; }
      }
    }
  }
  return user;
}

// Read and return the uptime of a process
long LinuxParser::UpTime(int pid) { 
  string token{};
  string line{};
  long clock_ticks = 0;
  std::ifstream filestream(kProcDirectory + "/" + to_string(pid) + kStatFilename);
  if (filestream.is_open()) {
    std::getline(filestream, line);
    std::istringstream stream(line);
    // Extract only the starttime token
    for (int i=0; i<22; i++) { stream >> token; }
    clock_ticks = stol(token);  
    return (clock_ticks/sysconf(_SC_CLK_TCK));  // To convert from clock ticks to seconds
  }
  return 0;
}

// Read proc stat file attributes
int LinuxParser::ReadProcStatFile(string attribute) {
  string line{};
  string key{};
  string value{};
  std::ifstream filestream(kProcDirectory + kStatFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == attribute) { return stoi(value); }
      }
    }
  }
  return 0;
}

// Read proc pid status file attributes
int LinuxParser::ReadProcPidStatusFile(int pid, string attribute) {
  string line, key;
  string value{};
  std::ifstream filestream(kProcDirectory + "/" + to_string(pid) + kStatusFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == attribute) {  return stoi(value); }
      }
    }
  }
  return 0;
}