#include "processor.h"

// Return the aggregate CPU utilization
float Processor::Utilization() { 
   LinuxParser::UpdateCpuUtilization();
   return (LinuxParser::active_jiffies/(LinuxParser::jiffies * 1.0)); 
}