#include <iostream>
#include <pcap/pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
//#include <netinet/udp.h>
//#include <netinet/tcp.h>
//#include <netinet/ip_icmp.h>
//...
#include <arpa/inet.h>


using namespace std;

void packet_handler(u_char *accumulator, const struct pcap_pkthdr *metadata, const u_char *data){
    auto eh = reinterpret_cast <const struct ether_header*>(data);
    //cout << hex << ntohs(eh->ether_type) << endl;
    if(ntohs(eh->ether_type) != ETHERTYPE_IP){
        cout << "not an IP packet..." << endl;
        return;
    }
    char ip_src[16], ip_dst[16];
    
    const struct iphdr* ih = reinterpret_cast <const struct iphdr*>(eh+1);
    //src addr
    inet_ntop(
        AF_INET,
        reinterpret_cast<const void *>(&ih->saddr),
        ip_src,
        sizeof(ip_src)
    );
    
    //dst addr
    inet_ntop(
        AF_INET,
        reinterpret_cast<const void *>(&ih->daddr),
        ip_dst,
        sizeof(ip_dst)
    );
    //protocol field is judt 1 byte --> no issues with endianness.

    auto protocol = (ih->protocol == IPPROTO_TCP) ? "TCP" : "";
    cout << "ip source: " << ip_src << ", ip destination: " << ip_dst << " " << protocol << endl;


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

    //-1 means: infinite loop!
    if(pcap_loop(handle,-1,packet_handler,NULL) == -1){
        cerr << "<some error message should be displayed here...>" << endl;
        return(2);
    }
    
    return 0;
}
