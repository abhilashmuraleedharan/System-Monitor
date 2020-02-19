#include "processor.h"

// Return the aggregate CPU utilization
float Processor::Utilization() { 
   return (LinuxParser::ActiveJiffies()/(LinuxParser::Jiffies() * 1.0)); 
}