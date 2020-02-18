#include <string>

#include "format.h"

using std::string;
using std::to_string;

/*
 * Formats time in seconds into readable string
 * Input : Elapsed time in seconds
 * Output: HH:MM:SS formatted string
 */
string Format::ElapsedTime(long time) {
   int hours=0, minutes=0, seconds=0;
   string HH{};
   string MM{};
   string SS{};
   hours = time / 3600;
   time  = time % 3600;
   minutes = time / 60;
   seconds = time % 60;
   if (hours < 10) { HH = "0" + to_string(hours); }
   else { HH = to_string(hours); }
   if (minutes < 10) { MM = "0" + to_string(minutes); }
   else { MM = to_string(minutes); }
   if (seconds < 10) { SS = "0" + to_string(seconds); }
   else { SS = to_string(seconds); }

   return HH + ":" + MM + ":" + SS; 
}
