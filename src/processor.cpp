#include "processor.h"

// Return the aggregate CPU utilization
double Processor::Utilization() const { 
   LinuxParser::UpdateCpuUtilization();
   return (LinuxParser::active_jiffies/(LinuxParser::jiffies * 1.0)); 
}