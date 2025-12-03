#include <stdio.h>

extern "C" int darwinkit_tool_main(int argc, char** argv, char** envp);

int main(int argc, char** argv, char** envp) {
    darwinkit_tool_main(argc, argv, envp);
}
