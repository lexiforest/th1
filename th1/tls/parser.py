import dpkt
import ipaddress

import io

from .signature import TLSClientHelloSignature


def parse_pcap(pcap: bytes, port: int = 443, raw_ip: bool = False) -> list[dict]:
    """Extract TLS Client Hello records from a pcap file.

    Parameters
    ----------
    pcap
        A file-like object in pcap format.

    Returns
    -------
    client_hellos: list[dict]
        List of TLS Client Hello records found in the pcap file.
        Each record is a dictionary of the form
        {
            "ip_ver": 4,
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "src_port": 1111,
            "dst_port": 2222
            "client_hello": b"..."
        }
        The value of "client_hello"is the TLS portion of each packet,
        i.e. the with IP/TCP portions removed.
    """
    client_hellos = []
    for _, buf in dpkt.pcap.UniversalReader(io.BytesIO(pcap)):
        if not raw_ip:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP) and not isinstance(
                eth.data, dpkt.ip6.IP6
            ):
                continue
            ip = eth.data
        else:
            ip = dpkt.ip.IP(buf)
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue
        tcp = ip.data
        if tcp.dport != port or not tcp.data:  # type: ignore
            continue
        # We hope that the record is in a single TCP packet
        # and wasn't split across multiple packets. This is usually the case.
        tls = dpkt.ssl.TLSRecord(tcp.data)
        # Check if it's a Handshake record
        if tls.type != 0x16:  # type: ignore
            continue
        handshake = dpkt.ssl.TLSHandshake(tls.data)
        # Check if it's a Client Hello
        if handshake.type != 0x01:  # type: ignore
            continue
        # Return the whole TLS record
        client_hellos.append(
            {
                "ip_ver": 4 if isinstance(ip, dpkt.ip.IP) else 6,
                "src_ip": str(ipaddress.ip_address(ip.src)),  # type: ignore
                "dst_ip": str(ipaddress.ip_address(ip.dst)),  # type: ignore
                "src_port": tcp.sport,  # type: ignore
                "dst_port": tcp.dport,  # type: ignore
                "client_hello": tcp.data,
                "signature": TLSClientHelloSignature.from_bytes(tcp.data),
            }
        )

    return client_hellos
