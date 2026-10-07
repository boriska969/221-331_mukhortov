#ifndef LR1_INTEGRITY_HPP
#define LR1_INTEGRITY_HPP

#include <string>

namespace lr1 {

bool isDebuggerAttached();

bool computeTextSegmentHash(std::string& hexOut, std::string& error);

bool isTextSegmentIntact(std::string& error);

}

#endif
