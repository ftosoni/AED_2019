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
    "strings"
    "time"
)

var (
    device      string = ""
    snapshotLen int32  = 1024
    promiscuous bool   = false
    err         error
    timeout     time.Duration = 30 * time.Second
    handle      *pcap.Handle

    isLazy bool = false
    isNoCopy bool = false
)

type status uint8
const (
    CLOSED  status = iota
    SYN_RECEIVED
    SYN_SENT    
    ESTABLISHED
    FIN_WAIT_1
    FIN_WAIT_2
    CLOSING
    CLOSE_WAIT
    LAST_ACK
    USELESS
)

type flow_key struct {
    addr1           uint32
    addr2           uint32
    port1           uint16
    port2           uint16
}

type flow_value struct {
    pkts            uint32
    bytes           uint32
    starting_time   time.Time
    tot_duration    time.Duration
    incarnations    uint32
    s1              status
    s2              status
}

func main() {
    if(len(os.Args) != 1+2){
        fmt.Println("Usage is:",os.Args[0]," <device | pcapfile> <#tcp_pkts>")
        return
    }

    //args
    device = os.Args[1]
    limit,err := strconv.Atoi(os.Args[2])
    if err!=nil {
        fmt.Println("<#tcp_pkts> must be an integer")
        return
    }

    //map maintaining sensed/processed data
    m := make(map[uint32]map[flow_key]flow_value)

    // Open device or pcapfile
    isFile := strings.HasSuffix(device, ".pcap")
    if isFile {
        handle, err = pcap.OpenOffline(device)
    } else {
        handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
    }
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    count := 0
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packetSource.DecodeOptions.Lazy = isLazy
    packetSource.DecodeOptions.NoCopy = isNoCopy
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
            fmt.Println("-",int2ipv4(k2.addr1),"(port",k2.port1,") <---->",int2ipv4(k2.addr2), "(port",k2.port2,")")
            fmt.Println("\tpkts:",v2.pkts)
            fmt.Println("\tbytes:",v2.bytes)
            if v2.incarnations>0 {
                fmt.Println("\tavg duration:",time.Duration(uint64(v2.tot_duration)/uint64(v2.incarnations)))
            } else {
                fmt.Println("\tavg duration: NO DATA")
            }
            fmt.Println("\t# TCP sessions:",v2.incarnations)

        }
        fmt.Println()
    }

}

func compute_flow_key(saddr uint32, daddr uint32, sport uint16, dport uint16) (flow_key,bool) {
    var fk flow_key
    is1to2 := saddr < daddr
    if is1to2 {
        fk = flow_key{
            saddr,
            daddr,
            sport,
            dport,
        }
    }else{
        fk = flow_key{
            daddr,
            saddr,
            dport,
            sport,
        }
    }
    return fk, is1to2
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
            fk,is1to2 := compute_flow_key(
                to_uint32(ip.SrcIP),
                to_uint32(ip.DstIP),
                uint16(tcp.SrcPort),
                uint16(tcp.DstPort),
            )
            hash := hashing(fk)
            prev_s1,prev_s2 := CLOSED,CLOSED
            _,present := (*m)[hash]
            if(!present){
                (*m)[hash] = make(map[flow_key]flow_value)
            }
            fv,present2 := (*m)[hash][fk]
            if present2 {
                prev_s1 = fv.s1
                prev_s2 = fv.s2
            }

            var new_status_sender, new_status_receiver status
            var isStatusChanged bool

            if is1to2 {
                //addr1 sent to addr2, so new status for s1
                new_status_sender = compute_new_status_sender(prev_s2,syn,fin)
                new_status_receiver,isStatusChanged = compute_new_status_receiver(prev_s1,syn,fin,ack)
            }else{
                //addr2 sent to addr1, so new status for s2
                new_status_sender = compute_new_status_sender(prev_s1,syn,fin)
                new_status_receiver,isStatusChanged = compute_new_status_receiver(prev_s2,syn,fin,ack)
            }


            //updating (or creating) flow_value
            if present2 {
                fv.bytes += bytes
                fv.pkts += 1
            }else{
                fv = flow_value{
                    1,      //pkts
                    bytes,  //bytes
                    time.Now(),    //starting_time
                    0,      //tot_duration
                    0,      //incarnations
                    CLOSED, //status 1
                    CLOSED, //status 2
                }
            }
            if is1to2 {
                fv.s1 = new_status_receiver
                fv.s2 = new_status_sender
            } else {
                fv.s2 = new_status_receiver
                fv.s1 = new_status_sender
            }

            //print new status
            var str_is1to2, str_ack, str_fin, str_syn string
            if ack {str_ack = "A"} else {str_ack = "_"}
            if syn {str_syn = "S"} else {str_syn = "_"}
            if fin {str_fin = "F"} else {str_fin = "_"}
            fmt.Println(int2ipv4(fk.addr1),"(port",fk.port1,") <---->",int2ipv4(fk.addr2), "(port",fk.port2,")",fv.s1,fv.s2,str_syn,str_fin,str_ack,str_is1to2,time.Since(fv.starting_time))

            //update when opening or closing connections
            if isStatusChanged {
                if fv.s1 == ESTABLISHED && fv.s2 == ESTABLISHED {
                    fv.starting_time = time.Now()
                }else if fv.s1 == CLOSED && fv.s2 == CLOSED {
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

func compute_new_status_sender(
    prev_status status,
    syn bool,
    fin bool,
    ) status {
    
    var new_status status = prev_status

    switch prev_status {
    case CLOSED :
        if syn {
            new_status = SYN_SENT
        }
    case ESTABLISHED :
        if fin {
            new_status = FIN_WAIT_1
        }
    case CLOSE_WAIT :
        if fin {
            new_status = LAST_ACK
        }
    }

    return new_status
}

func compute_new_status_receiver(
    prev_status status,
    syn bool,
    fin bool,
    ack bool,
    ) (status,bool) {

    var new_status status = prev_status

    switch prev_status {
    case CLOSED :
        if syn {
            new_status = SYN_RECEIVED
        }
    case SYN_RECEIVED :
        if ack {
            new_status = ESTABLISHED
        }
    case SYN_SENT :
        if syn {
            if ack {
                new_status = ESTABLISHED
            } else {
                new_status = SYN_RECEIVED
            }
        }
    case ESTABLISHED :
        if fin {
                new_status = CLOSE_WAIT
        }
    case FIN_WAIT_1 :
        if fin {
            new_status = CLOSING
        } else if ack {
            new_status = FIN_WAIT_2
        }
    case FIN_WAIT_2 :
        if fin {
            new_status = CLOSED
        }
    case CLOSING :
        if ack {
            new_status = CLOSED
        }
    //case CLOSE_WAIT, nothing to do here...
    case LAST_ACK :
        if ack {
            new_status = CLOSED
        }
    }

    return new_status, new_status!=prev_status
}


func hashing(fk flow_key) uint32 {
    var u1,u2,u3 uint32
    
    //u1
    //simply the source address
    u1 = fk.addr1

    //u2
    //bits at odd poistions in destination address now occupy even positions, and vice versa
    u2 = ((fk.addr2 & 0x55555555) << 1) | ((fk.addr2 & 0xaaaaaaaa) >> 1)

    //u3
    //source port bits are shifted to most significant and least significant positions
    //destination port bits occupy central positions
    var port1_32,port2_32 uint32 = uint32(fk.port1),uint32(fk.port2)
    u3 = ((port1_32 >> (16-3)) << (32-3)) | (port2_32 << (32-3-16)) | (port1_32 & ((1 << (16-3)) - 1))
    
    //exclusive or operation is performed
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

