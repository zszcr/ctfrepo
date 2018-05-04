#include <stdio.h>
#include <unistd.h>

void init(){
    setvbuf(stdout, NULL, _IOLBF, 0);
}

void welcome(){
    write(1, "Welcome to Sniperoj!\n", 21);
}

void vuln(){
    char buffer[8] = {0};
    read(0, buffer, 0x30);
}

int main(){
    init();
    welcome();
    vuln();
    return 0;
}
