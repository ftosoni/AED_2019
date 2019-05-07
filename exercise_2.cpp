#include <iostream>
#include <pcap/pcap.h>

using namespace std;

void packet_handler(
            u_char *accumulator,
            const struct pcap_pkthdr *metadata,
            const u_char *data
            )
{  
    auto counter_ptr = reinterpret_cast <u_int*>(accumulator);
    auto counter = ++(*counter_ptr);
    cout << "pkt nr: " << counter << endl;
}


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
    

    u_int counter = 0;
    if(pcap_loop(handle,10,packet_handler,(u_char*)&counter) == -1){
        cerr << "Error!" << endl;
    }
    
    return 0;
}

int main2(int argc, char *argv[]){
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
    cout << (metadata->caplen) << endl;
    cout << (metadata->len) << endl;
    cout << (metadata->ts.tv_sec) << endl;

    for(int i=0; i<64; i++)
        cout << pkt[i];
    cout << endl;
    
    return 0;
}