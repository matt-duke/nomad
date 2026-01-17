package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/netsampler/goflow2/v3/decoders/netflow"
	"github.com/netsampler/goflow2/v3/decoders/utils"
	"github.com/netsampler/goflow2/v3/utils/templates"
)

var (
	netFlowRegistry = templates.Registry(templates.NewInMemoryRegistry(nil))
)

func init() {
	netFlowRegistry.Start()
}

func main() {
	fmt.Println("starting server")
	addr, err := net.ResolveUDPAddr("udp", ":2550")
	if err != nil {
		fmt.Println("Error resolving address:", err)
		os.Exit(1)
	}

	fmt.Println("waiting for connection")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println(err)
	}
	handle_connection(conn)
}

func handle_connection(conn *net.UDPConn) {
	fmt.Println("connected")
	defer conn.Close()

	for {
		payload := make([]byte, 9000)
		_, addr, _ := conn.ReadFromUDP(payload)
		buf := bytes.NewBuffer(payload)
		templates := netFlowRegistry.GetSystem(addr.String())

		// var version uint16
		// if err := utils.BinaryDecoder(buf, &version); err != nil {
		// 	fmt.Println(err)
		// }

		var version uint16
		if err := utils.BinaryDecoder(buf, &version); err != nil {
			fmt.Println(err)
		}

		pkt := new(netflow.NFv9Packet)
		switch version {
		case 9:
			if err := netflow.DecodeMessageNetFlow(buf, templates, pkt); err != nil {
				fmt.Println(err)
			}
		}

		for _, flowSet := range pkt.FlowSets {
			switch tFlowSet := flowSet.(type) {
			case netflow.DataFlowSet:
				for _, record := range tFlowSet.Records {
					for _, df := range record.Values {
						session := Session{}

						v, ok := df.Value.([]byte)
						if !ok {
							continue
						}

						if df.PenProvided {
							continue
						}

						switch df.Type {
						case netflow.NFV9_FIELD_L4_SRC_PORT:
							session.SrcPort = binary.BigEndian.Uint16(v)
						case netflow.NFV9_FIELD_L4_DST_PORT:
							session.DstPort = binary.BigEndian.Uint16(v)
						case netflow.NFV9_FIELD_IN_BYTES:
							session.InBytes = uint64(binary.BigEndian.Uint32(v))
						case netflow.NFV9_FIELD_OUT_BYTES:
							session.OutBytes = uint64(binary.BigEndian.Uint32(v))
						}

						fmt.Println(session)
					}
				}
			}
		}
	}
}
