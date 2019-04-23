#include <string>
#include <fstream>
#include <iostream>
#include <stdlib.h>
using namespace std;

int main(){
        std::ifstream mid_file("/etc/machine-id");

        //Get Machine-ID
        std::string mid, hn, unique_serv_name;
        std::getline(mid_file, mid);
        //cout<<"M_ID : "<<mid<<"\n";

        //Get Hostname
        std::ifstream hn_file("/etc/hostname");
        std::getline(hn_file, hn);
        //cout<<"M_ID : "<<hn<<"\n";

        //Append Hostname and MachineId -- generate unique name (For service)
        unique_serv_name = hn + mid;
        //cout<<"Unique Service Name : "<<unique_serv_name<<"\n";

        std::string cmd_str = "hostnamectl set-hostname "+unique_serv_name;
        cout<<cmd_str<<"\n";
	const char *command = cmd_str.c_str();
        system(command);
        return 0;
}

