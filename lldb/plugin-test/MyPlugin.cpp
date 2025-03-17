#include <lldb/API/LLDB.h>
#include <lldb/API/SBCommandInterpreter.h>
#include <lldb/API/SBCommandPluginInterface.h>
#include <lldb/API/SBCommandReturnObject.h>
#include <lldb/API/SBDebugger.h>
#include <iostream>

using namespace lldb;

class MyHelloCommand : public SBCommandPluginInterface {
public:
    bool DoExecute(SBDebugger debugger, char** command, SBCommandReturnObject& result) override {
        result.Printf("Hello from LLDB plugin!\n");
        result.SetStatus(eReturnStatusSuccessFinishResult);
        return true;
    }
};

// Plugin entry point
bool __attribute__((visibility("default"))) lldb_initialize(SBDebugger debugger) {
    SBCommandInterpreter interpreter = debugger.GetCommandInterpreter();
    SBCommand return_obj;
    
    interpreter.AddCommand("my_hello", new MyHelloCommand(), "Custom LLDB command to print a message.");
    
    return true;
}
