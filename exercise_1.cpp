#include <iostream>
#include <pcap/pcap.h>

using namespace std;

int main(int argc, char *argv[]){
    if(argc!=2){
        cout << "Usage is: " << argv[0] << " <inf_name>" << endl;
        return -1;
    }

    pcap_t *handle;
    char *errbuf = new char[1000];
    handle = pcap_open_live(argv[1],64,1,1000,errbuf);
    if(handle==NULL){
        cerr << "Couldn't open device: " << errbuf << endl;
        return(2);
    }

    auto metadata = new pcap_pkthdr();
    const u_char *pkt = pcap_next(handle, metadata);
    cout << "caplen: " << (metadata->caplen) << endl;
    cout << "len: " << (metadata->len) << endl;
    
    return 0;
}