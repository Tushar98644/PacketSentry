package pcap

import (
    "fmt"

    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"

    "github.com/Tushar98644/PacketSentry/pkg/config"
    "github.com/Tushar98644/PacketSentry/pkg/constants"
)

// OpenHandle opens the pcap handle (live or offline),
// using cfg for mode & filename, and constants for device/timeouts.
func OpenHandle(cfg *config.Config) (*pcap.Handle, error) {
    if cfg.LiveCapture {
        return pcap.OpenLive(
            constants.Device,
            constants.SnapshotLen,
            constants.Promiscuous,
            constants.Timeout,
        )
    }

    fname := fmt.Sprintf(
        "%s/%s%s",
        constants.PacketFolder,
        cfg.FileName,
        constants.PacketFileType,
    )
    return pcap.OpenOffline(fname)
}

// ReadPackets spins up a goroutine that reads from handle
// and sends every packet into the returned channel.
func ReadPackets(handle *pcap.Handle) <-chan gopacket.Packet {
    src := gopacket.NewPacketSource(handle, handle.LinkType())
    ch := make(chan gopacket.Packet)
    go func() {
        defer close(ch)
        for pkt := range src.Packets() {
            ch <- pkt
        }
    }()
    return ch
}
