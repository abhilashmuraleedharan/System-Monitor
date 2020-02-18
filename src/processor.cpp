#include "processor.h"
#include "linux_parser.h"

// Return the aggregate CPU utilization
float Processor::Utilization() { 
   return (LinuxParser::ActiveJiffies()/(LinuxParser::Jiffies() * 1.0)) * 100; 
}