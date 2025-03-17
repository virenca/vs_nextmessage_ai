#include <iostream>
#include <lldb/API/LLDB.h>

int main() {
    lldb::SBDebugger::Initialize();
    lldb::SBDebugger debugger = lldb::SBDebugger::Create(false);

    if (debugger.IsValid()) {
        std::cout << "LLDB API initialized successfully!" << std::endl;
    } else {
        std::cerr << "Failed to initialize LLDB API!" << std::endl;
    }

    lldb::SBDebugger::Terminate();
    return 0;
}
