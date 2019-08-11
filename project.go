package main

import (
    "encoding/binary"
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "log"
    "net"
    "os"
    "strconv"
    "time"
)

var (
    device      string = "wlp3s0"
    snapshotLen int32  = 1024
    promiscuous bool   = false
    err         error
    timeout     time.Duration = 30 * time.Second
    handle      *pcap.Handle
)

type status uint8
const (
    CLOSED  status = iota
    SYN     
    SYNACK  
    OPEN    
    FIN     
)

type flow_key struct {
    saddr           uint32
    daddr           uint32
    sport           uint16
    dport           uint16
}

type flow_value struct {
    pkts            uint32
    bytes           uint32
    starting_time   time.Time
    tot_duration    time.Duration
    incarnations    uint32
    s               status
}

var mii int = 0

func main() {
    if(len(os.Args) != 1+1){
        fmt.Println("Usage is:",os.Args[0]," <#pkts>")
        return
    }

    limit,err := strconv.Atoi(os.Args[1])
    if err!=nil {
        fmt.Println("#pkts must be an integer")
        return
    }

    m := make(map[uint32]map[flow_key]flow_value)

    // Open device
    handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    count := 0
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        if processPacketInfo(packet,&m) {
            count ++
        }
        if count >= limit {
            break
        }
        fmt.Println("______________________________")
    }

    print_statistics(&m)
}

func print_statistics(m *map[uint32]map[flow_key]flow_value) {
    for k,v := range *m {
        fmt.Println("hash:",k)
        for k2,v2 := range v {
            fmt.Println("- from",int2ipv4(k2.saddr),"(port",k2.sport,") to",int2ipv4(k2.daddr), "(port",k2.dport,")")
            fmt.Println("\tpkts:",v2.pkts)
            fmt.Println("\tbytes:",v2.bytes)
            if v2.incarnations>0 {
                fmt.Println("\tavg duration:",time.Duration(uint64(v2.tot_duration)/uint64(v2.incarnations)))
            } else {
                fmt.Println("\tavg duration: NO DATA")
            }
        }
        fmt.Println()
    }

}

func processPacketInfo(packet gopacket.Packet, m *map[uint32]map[flow_key]flow_value) bool {

    isTCP := false

    // L3 - Let's see if the packet is IP
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
        fmt.Println("IP layer detected.")
        ip, _ := ipLayer.(*layers.IPv4)

        // IP layer variables:
        // Version (Either 4 or 6)
        // IHL (IP Header Length in 32-bit words)
        // TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
        // Checksum, SrcIP, DstIP
        fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)

        // L4 - Let's see if the packet is TCP
        tcpLayer := packet.Layer(layers.LayerTypeTCP)
        if tcpLayer != nil {
            isTCP = true
            fmt.Println("TCP layer detected.")
            tcp,_ := tcpLayer.(*layers.TCP)

            // TCP layer variables:
            // SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
            // Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
            fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
            syn := tcp.SYN
            fin := tcp.FIN
            ack := tcp.ACK
            if(syn) { mii++}

            // L5 - applicationLayer contains the payload
            var bytes uint32
            bytes = 0
            applicationLayer := packet.ApplicationLayer()
            if applicationLayer != nil {
                fmt.Println("Application layer/Payload found.")
                bytes = uint32(len(applicationLayer.Payload()))
                fmt.Printf("payload length: %d\n", bytes)
            }//end L5
                
            //processing: from here

            //check previous TCP status
            fk := flow_key{
                to_uint32(ip.SrcIP),
                to_uint32(ip.DstIP),
                uint16(tcp.SrcPort),
                uint16(tcp.DstPort),
            }
            hash := hashing(fk)
            prev_status := CLOSED
            _,present := (*m)[hash]
            if(!present){
                (*m)[hash] = make(map[flow_key]flow_value)
            }
            fv,present2 := (*m)[hash][fk]
            if present2 {
                prev_status = fv.s
            }

            //compute new TCP status
            new_status := compute_new_status(prev_status,syn,fin,ack)

            //updating (or creating) flow_value
            if(present2){
                fv.bytes += bytes
                fv.pkts += 1
                fv.s = new_status
            }else{
                fv = flow_value{
                    1,      //pkts
                    bytes,  //bytes
                    time.Now(),    //starting_time
                    0,      //tot_duration
                    0,      //incarnations
                    new_status, //status
                }
            }

            //update when opening or closing connections
            if new_status!=prev_status {
                if new_status == OPEN {
                    fv.starting_time = time.Now()
                }else if new_status == CLOSED {
                    elapsed := time.Since(fv.starting_time)
                    fv.tot_duration += elapsed
                    fv.incarnations ++
                }
            }

            (*m)[hash][fk] = fv
            //end processing        
        }//end L4
    }//end L3



    // Iterate over all layers, printing out each layer type
    fmt.Println("All packet layers:")
    for _,layer := range packet.Layers() {
        fmt.Println("- ", layer.LayerType())
    }

    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        fmt.Println("Error decoding some part of the packet:", err)
    }

    return isTCP
}

func compute_new_status(
    prev_status status,
    syn bool,
    fin bool,
    ack bool,
    ) status {

    var new_status status

    switch prev_status {
    case CLOSED :
        if syn {
            if ack {
                new_status = SYNACK
            } else {
                new_status = SYN
            }
        }
    case SYN :
        if syn && ack {
            new_status = OPEN
        }
    case SYNACK :
        if ack {
            new_status = OPEN
        }
    case OPEN :
        if fin {
            if ack {
                new_status = CLOSED
            } else {
                new_status = FIN
            }
        }
    case FIN :
        if ack {
            new_status = CLOSED
        }
    default :
        new_status = prev_status
    }

    return new_status
}


func hashing(fk flow_key) uint32 {
    var u1,u2,u3 uint32
    
    //u1
    u1 = fk.saddr

    //u2
    u2 = ((fk.daddr & 0x55555555) << 1) | ((fk.daddr & 0xaaaaaaaa) >> 1)

    //u3
    var sport_32,dport_32 uint32 = uint32(fk.sport),uint32(fk.dport)
    u3 = ((sport_32 >> (16-3)) << (32-3)) | (dport_32 << (32-3-16)) | (sport_32 & ((1 << (16-3)) - 1))

    return u1 ^ u2 ^ u3
}

//byte array must have dimension 4
func to_uint32(b net.IP) uint32 {
    var tmp uint32
    tmp = 0
    for i:=0; i<4; i++ {
        tmp <<= 8
        tmp |= uint32(b[i])
    }
    return tmp
}

//byte array must have dimension 2
func to_uint16(b []byte) uint16 {
    var tmp uint16
    tmp = uint16(b[0]) << 8 | uint16(b[1])
    return tmp
}

func int2ipv4(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

