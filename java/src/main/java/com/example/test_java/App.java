package com.example.test_java;

import java.io.EOFException;
import java.net.Inet4Address;
import java.net.UnknownHostException;

import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.Builder;
import org.pcap4j.packet.Packet;

public class App {

  private static final String INPUT_FILE = "input.pcap";
  private static final String OUTPUT_FILE = "output.pcap";
  private static final String ANONYMIZED_IP = "000.000.0.0";

  public static void main(String[] args) {
    try {
      PcapHandle handle = Pcaps.openOffline(INPUT_FILE, PcapHandle.TimestampPrecision.NANO);
      PcapDumper dumper = handle.dumpOpen(OUTPUT_FILE);
      Packet packet;

      while (true) {
        try {
          packet = handle.getNextPacketEx();
          if (packet.contains(IpV4Packet.class)) {
            packet = anonymizeIpV4Packet(packet);
          }
          dumper.dump(packet, handle.getTimestamp());
        } catch (EOFException e) {
          break;
        }
      }

      dumper.close();
      handle.close();
    } catch (Exception e1) {
      // TODO Auto-generated catch block
      e1.printStackTrace();
    }
  }

  private static Packet anonymizeIpV4Packet(Packet packet) throws UnknownHostException {
    IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
    Builder ipV4Builder = new Builder(ipV4Packet);

    Inet4Address anonymizedAddress = (Inet4Address) Inet4Address.getByName(ANONYMIZED_IP);

    ipV4Builder.srcAddr(anonymizedAddress);
    ipV4Builder.dstAddr(anonymizedAddress);
    ipV4Builder.correctChecksumAtBuild(true);
    ipV4Builder.correctLengthAtBuild(true);

    Packet newPacket = packet.getBuilder().getOuterOf(IpV4Packet.Builder.class).payloadBuilder(ipV4Builder).build();
    return newPacket;
  }
}
