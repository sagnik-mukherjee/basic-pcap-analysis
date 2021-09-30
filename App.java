/**
 * App.java: Class, basic exercise in packet capture,
 * based on Kaitoy's pcap4j library. Accepts 
 * .pcap file, and outputs packet amounts and bandwidth.
 * @author Sagnik Mukherjee
 */
package com.github.username;

import java.io.IOException;
import java.net.Inet4Address;

import com.sun.jna.Platform;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class App 
{
    static int packetTotal = 0;
    static int UDPTotal = 0;
    static int TCPTotal = 0;
    static float byteTotal = 0;

    static double firstPktTime = 0;
    static double lastPktTime = 0;
    static boolean firstPacketReached = false;

    /**
     * Main driver method, process passed pcap file.
     */
    public static void main(String[] args) throws PcapNativeException, 
    NotOpenException 
    {
        if (args.length != 1) {
            System.out.println("ERROR: Singular filename argument expected.");
            return;
        }

        final PcapHandle handle;
        try {
            handle = Pcaps.openOffline(args[0]);
        } catch (PcapNativeException p) {
            System.out.println("ERROR: Failed to create PcapHandle object/" 
                + "File not found.");
            return;
        }

        PacketListener listener = new PacketListener() 
        {
            public void gotPacket(Packet packet) 
            {
                if (!firstPacketReached) {
                    firstPktTime = (double) handle.getTimestamp().getTime();
                    firstPacketReached = true;
                }

                /* It is unknown if a given packet is the last packet in the
                 * input stream, so we continue to store timestamps until
                 * the final PacketListener call.
                 */
                lastPktTime = (double) handle.getTimestamp().getTime();

                packetTotal = 1 + packetTotal;
                byteTotal += (float) packet.length();

                if (packet.get(TcpPacket.class) != null)
                    TCPTotal += 1;

                if (packet.get(UdpPacket.class) != null)
                    UDPTotal += 1;
            }
        };

        try {
            // actual maxPackets is unknown, so we loop until .pcap hits EOF
            int maxPackets = -1;
            handle.loop(maxPackets, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        double totalTime = lastPktTime - firstPktTime;
        totalTime /= 1000.0;

        System.out.println("Total number of packets, " + packetTotal);
        System.out.println("Total number of UDP packets, " + UDPTotal);
        System.out.println("Total number of TCP packets, " + TCPTotal);
        System.out.println("Total bandwidth of the packet trace in Mbps, " 
            + byteTotal / totalTime / 125000.0);

        handle.close();
    }
}
