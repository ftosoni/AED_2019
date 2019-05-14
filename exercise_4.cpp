#include <iostream>
#include <pcap/pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
//#include <netinet/udp.h>
//#include <netinet/tcp.h>
//#include <netinet/ip_icmp.h>
//...
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>

using namespace std;

/*
* 802.1Q header structure.
*/
struct vlan_ethhdr {
    u_char h_dest[ETHER_ADDR_LEN];
    u_char h_source[ETHER_ADDR_LEN];
    u_int16_t h_vlan_proto;
    u_int16_t h_vlan_TCI;
    u_int16_t h_vlan_encapsulated_proto;
};

class PCAP_IP_tap 
{ 
  private:
    char m_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    static void callback(
                    u_char *state,
                    const struct pcap_pkthdr *metadata,
                    const u_char *data){
        auto tmp = reinterpret_cast<PCAP_IP_tap*>(state);
        tmp->packet_handler(metadata,data);
    }

  public:

    //Constructor
    PCAP_IP_tap(const char* iface, int snaplen,
               bool promisc, int to_ms){
        int promisc_integer = promisc ? 1 : 0;
        this->handle = pcap_open_live(iface,snaplen,promisc_integer,to_ms,this->m_errbuf);
        if(handle==NULL){
            cerr << "Couldn't reach interface: " << this->m_errbuf << endl;
        }
    }

    PCAP_IP_tap(const char* iface){
        this->handle = pcap_open_offline(iface,this->m_errbuf);
        if(handle==NULL){
            cerr << "Couldn't open file: " << this->m_errbuf << endl;
        }
    }

    ~PCAP_IP_tap(){
        pcap_close(this->handle);
    }
  
    // Member Functions() 
    void loop(int n) 
    { 
        auto ref = reinterpret_cast<u_char*>(this);
        if(pcap_loop(this->handle,n,PCAP_IP_tap::callback,ref) == -1){
            cerr << "<some error message should be displayed here...>" << endl;
            return;
        }
    }

    void packet_handler(const struct pcap_pkthdr *metadata,const u_char *data){
            char ip_src[16], ip_dst[16];
            auto eh = reinterpret_cast <const struct ether_header*>(data);

            const struct vlan_ethhdr *vlan_eh = nullptr;

            if(ntohs(eh->ether_type) == ETHERTYPE_VLAN){
                vlan_eh = reinterpret_cast <const struct vlan_ethhdr*>(data);
                if(ntohs(vlan_eh->h_vlan_encapsulated_proto) != ETHERTYPE_IP){
                    cout << "vlan eth, not an IP packet..." << endl;
                    return;
                }
            }else{
                if(ntohs(eh->ether_type) != ETHERTYPE_IP){
                    cout << "std eth, not an IP packet..." << endl;
                    return;
                }
            }
            const struct iphdr* ih = (vlan_eh) ?
                        reinterpret_cast <const struct iphdr*>(vlan_eh+1) :
                        reinterpret_cast <const struct iphdr*>(eh+1);

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
        }//end handler method
    }; 
  
int main(int argc, char *argv[]){
    if(argc!=3+1){
        cout << argc << endl;
        cout << "Usage is: " << argv[0] << " (-i|-f) <iface><filename> <num_pkts>" << endl;
        return -1;
    }
    //args
    bool fromFile;
    if(strcmp(argv[1],"-f")==0){
        fromFile = true;
    }else if (strcmp(argv[1],"-i")==0)
    {
        fromFile = false;
    }else{
        cout << "Usage is: " << argv[0] << " (-i|-f) <inf_name> <num_pkts>" << endl;
        return -1;
    }
    auto if_name = argv[2];
    int num_pkts = atoi(argv[3]);

    //pars
    int snaplen = 34;
    bool promisc = true;
    int to_ms = 1000;

    PCAP_IP_tap *device = NULL;
    if(fromFile){
        device = new PCAP_IP_tap(if_name);
    }else{
        device = new PCAP_IP_tap(if_name,snaplen,promisc,to_ms);
    }

    device->loop(num_pkts);

}