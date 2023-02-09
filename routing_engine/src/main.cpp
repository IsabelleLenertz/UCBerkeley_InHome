#include <iostream>
#include "layer3/Layer3Router.hpp"

int main(int argc, char *argv[])
{
    Layer3Router router;
    
    router.Initialize();
    
    router.MainLoop();

    return 0;
}
