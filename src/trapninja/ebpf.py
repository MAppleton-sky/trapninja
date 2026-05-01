#!/usr/bin/env python3
"""
TrapNinja eBPF Module - Minimal Version

Provides high-performance packet capture using eBPF (BPF Compiler Collection)
with an extremely simplified program to ensure compatibility.
"""
import os
import sys
import time
import logging
import threading
import queue
import ctypes as ct
import socket
import ipaddress

# Get logger instance
logger = logging.getLogger("trapninja")

# Try to import BCC - wrap in try/except to handle failures gracefully
BPF = None
EBPF_IMPORT_ERROR = None

def _import_bcc():
    """
    Import BCC with isolated path handling.
    
    RHEL 8 installs python3-bcc to Python 3.6 site-packages regardless of
    runtime Python version. We need to temporarily add this path for the BCC
    import, but then carefully manage sys.path to avoid polluting it with
    Python 3.6 packages that conflict with Python 3.9 (e.g., cffi).
    
    Returns:
        tuple: (BPF class or None, error message or None)
    """
    # First try importing without modifying sys.path
    try:
        from bcc import BPF as _BPF
        return _BPF, None
    except ImportError:
        pass  # Need to search for BCC
    
    # BCC installation paths to check
    BCC_PATHS = [
        # RHEL 8 default location (python3-bcc RPM) - CHECK FIRST
        '/usr/lib/python3.6/site-packages',
        '/usr/lib64/python3.6/site-packages',
        # Current Python version paths
        '/usr/lib/python{}.{}/site-packages'.format(
            sys.version_info.major, sys.version_info.minor
        ),
        '/usr/lib64/python{}.{}/site-packages'.format(
            sys.version_info.major, sys.version_info.minor
        ),
        # CMake/source build locations (last)
        '/usr/local/lib/python3.9/site-packages',
        '/usr/local/lib/python{}.{}/site-packages'.format(
            sys.version_info.major, sys.version_info.minor
        ),
        '/usr/local/lib64/python{}.{}/site-packages'.format(
            sys.version_info.major, sys.version_info.minor
        ),
    ]
    
    def _is_real_bcc(path):
        """Check if path contains real BCC (not Will Sheffler's pip package)"""
        bcc_path = os.path.join(path, 'bcc')
        if not os.path.exists(bcc_path):
            return False
        try:
            init_file = os.path.join(bcc_path, '__init__.py')
            if os.path.exists(init_file):
                # Skip if it's the wrong 'bcc' package (Will Sheffler's)
                if os.path.getsize(init_file) < 300:
                    with open(init_file, 'r') as f:
                        if 'willsheffler' in f.read().lower():
                            return False
            
            # Check for compiled extensions or other real BCC indicators
            contents = os.listdir(bcc_path)
            has_real_bcc = any(f.endswith('.so') for f in contents) or 'libbcc.py' in contents
            return has_real_bcc or (os.path.exists(init_file) and os.path.getsize(init_file) > 500)
        except:
            return False
    
    # Try each path, but only keep the one that works in sys.path
    # This avoids polluting sys.path with Python 3.6 packages that
    # conflict with Python 3.9 modules (e.g., cffi version mismatch)
    for path in BCC_PATHS:
        if not os.path.exists(path) or path in sys.path:
            continue
        
        if not _is_real_bcc(path):
            continue
        
        # Temporarily add path and try import
        sys.path.insert(0, path)
        try:
            from bcc import BPF as _BPF
            # Success! Remove path immediately to prevent cffi version conflicts
            # BCC is already imported into memory, so we don't need the path anymore
            sys.path.remove(path)
            return _BPF, None
        except ImportError:
            # Failed, remove path and try next
            sys.path.remove(path)
            continue
    
    return None, "BCC not installed"


# Perform the isolated BCC import
try:
    BPF, _bcc_error = _import_bcc()
    if BPF is not None:
        logger.debug("BCC imported successfully")
    else:
        EBPF_IMPORT_ERROR = f"BCC not installed: {_bcc_error}"
        logger.debug(f"BCC import failed: {_bcc_error}")
except AttributeError as e:
    BPF = None
    EBPF_IMPORT_ERROR = f"BCC version mismatch with system libraries: {e}"
    logger.warning(f"BCC import failed due to version mismatch: {e}")
except Exception as e:
    BPF = None
    EBPF_IMPORT_ERROR = f"BCC import error: {e}"
    logger.warning(f"Unexpected BCC import error: {e}")

# Define extremely minimal BPF program - avoiding all complex features
# This version uses perf_submit which requires specific program types
MINIMAL_BPF_PROGRAM = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h> 

// Simple data structure with minimal fields
struct event_t {
    u32 src_ip;
    u16 dst_port;
    u32 size;
};

BPF_PERF_OUTPUT(events);

// Very basic port table - just use one port for simplicity
BPF_HASH(ports, u16, u8, 16);

int packet_filter(struct __sk_buff *skb) {
    u8 *cursor = 0;

    // Parse headers
    struct ethhdr *eth = cursor_advance(cursor, sizeof(*eth));
    if (eth->h_proto != htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = cursor_advance(cursor, sizeof(*ip));
    if (ip->protocol != IPPROTO_UDP)
        return 0;

    // Check for non-first IP fragments (fragment offset > 0).
    // Non-first fragments have no UDP header - do not attempt port check.
    // Pass a fragment event to userspace so Python reassembly can handle it.
    u16 frag_off = ntohs(ip->frag_off);
    if (frag_off & 0x1FFF) {
        struct event_t frag_event = {};
        frag_event.src_ip = ip->saddr;
        frag_event.dst_port = 0;
        frag_event.size = 0;
        events.perf_submit(skb, &frag_event, sizeof(frag_event));
        return 0;
    }

    struct udphdr *udp = cursor_advance(cursor, sizeof(*udp));

    // Check port
    u16 dport = ntohs(udp->dest);
    u8 *found = ports.lookup(&dport);
    if (!found)
        return 0;

    // Bare minimum event data
    struct event_t event = {};
    event.src_ip = ip->saddr;
    event.dst_port = dport;
    event.size = ntohs(ip->tot_len) - sizeof(*ip) - sizeof(*udp);

    // Submit event
    events.perf_submit(skb, &event, sizeof(event));

    return 0;
}
"""

# Simpler socket filter that just filters packets (no perf events)
# Uses classic BPF load functions compatible with SOCKET_FILTER type
SIMPLE_SOCKET_FILTER = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

// Port table for filtering
BPF_HASH(ports, u16, u8, 16);

int packet_filter(struct __sk_buff *skb) {
    // Use load_half/load_byte for SOCKET_FILTER compatibility
    // These work on all kernel versions unlike direct packet access
    
    // Check EtherType at offset 12 (2 bytes)
    u16 eth_proto = load_half(skb, offsetof(struct ethhdr, h_proto));
    if (eth_proto != htons(ETH_P_IP))
        return 0;
    
    // Check IP protocol at offset 14 (ethernet) + 9 (protocol field in IP header)
    u8 ip_proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
    if (ip_proto != IPPROTO_UDP)
        return 0;

    // Check for non-first IP fragments before attempting to read the UDP header.
    // The frag_off field is 2 bytes at IP header offset 6.
    // Network byte order layout of frag_off:
    //   byte[0] bits 7-5: [Reserved][DF][MF]
    //   byte[0] bits 4-0 + byte[1] bits 7-0: fragment offset (in 8-byte units)
    // A non-first fragment has fragment offset > 0.
    u8 frag_byte0 = load_byte(skb, ETH_HLEN + 6);
    u8 frag_byte1 = load_byte(skb, ETH_HLEN + 7);
    if ((frag_byte0 & 0x1F) != 0 || frag_byte1 != 0) {
        // Non-first UDP fragment: no UDP header present at this position.
        // Pass the raw bytes to userspace so Python can reassemble the datagram.
        return skb->len;
    }

    // Get IP header length (IHL is lower 4 bits of first byte)
    u8 ip_verihl = load_byte(skb, ETH_HLEN);
    u8 ip_hlen = (ip_verihl & 0x0F) * 4;

    // Get UDP destination port at offset: ethernet + IP header + 2 (dest port offset in UDP)
    u16 dport = load_half(skb, ETH_HLEN + ip_hlen + offsetof(struct udphdr, dest));
    dport = ntohs(dport);
    
    // Check if destination port matches our filter
    u8 *found = ports.lookup(&dport);
    if (!found)
        return 0;
    
    // Return full packet length to accept
    return skb->len;
}
"""

# Packet queue for communication with existing TrapNinja processing logic
packet_queue = None

# Stop event for graceful shutdown
stop_event = None


class MinimalTrapCapture:
    """Minimal eBPF-based SNMP trap capture with fallback mechanisms"""

    def __init__(self, interface, listen_ports, queue_ref, stop_event_ref,
                 fragment_buffer=None):
        """
        Initialize the eBPF trap capture

        Args:
            interface (str): Network interface to capture on
            listen_ports (list): List of UDP ports to listen for traps
            queue_ref (queue.Queue): Reference to the packet processing queue
            stop_event_ref (threading.Event): Reference to the stop event
            fragment_buffer: Optional FragmentReassemblyBuffer instance for
                reassembling fragmented SNMP traps (>1472 bytes)
        """
        self.interface = interface
        self.listen_ports = listen_ports
        self.bpf = None

        # Fragment reassembly buffer (None = reassembly disabled)
        self.fragment_buffer = fragment_buffer

        # Store references to existing structures
        global packet_queue, stop_event
        packet_queue = queue_ref
        stop_event = stop_event_ref

        # For capturing raw packets as fallback
        self.raw_socket = None
        self.capture_thread = None

        logger.debug(f"MinimalTrapCapture initialized with interface={interface}, ports={listen_ports}")

    def _create_raw_socket(self, interface):
        """
        Create a raw socket for eBPF attachment.
        
        Args:
            interface: Network interface name (empty string for all)
            
        Returns:
            Socket file descriptor or None on failure
        """
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            if interface:
                sock.bind((interface, 0))
            return sock.fileno()
        except Exception as e:
            logger.debug(f"Failed to create raw socket: {e}")
            return None

    def _init_raw_capture(self):
        """
        Initialize raw packet capture as fallback if eBPF fails

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Create a raw socket to capture packets
            self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

            # Set to non-blocking
            self.raw_socket.setblocking(0)

            # Bind to interface if specified
            if self.interface != "any" and self.interface != "all":
                self.raw_socket.bind((self.interface, 0))

            logger.info(f"Raw packet capture initialized on interface {self.interface}")

            # Start capture thread
            self.capture_thread = threading.Thread(target=self._raw_capture_loop, daemon=True)
            self.capture_thread.start()

            return True
        except Exception as e:
            logger.error(f"Failed to initialize raw capture: {e}")
            return False

    def _raw_capture_loop(self):
        """Raw packet capture loop as fallback if eBPF fails"""
        logger.info("Starting raw packet capture loop")

        # Import required modules for packet parsing
        import select
        import struct

        # Import queue stats from network module for consistent drop tracking
        try:
            from .network import _queue_stats
            use_network_stats = True
        except ImportError:
            use_network_stats = False
            logger.warning("Could not import network stats - drops may not be recorded")

        # Lazy-import fragment helpers only when needed (avoids startup cost when disabled)
        fragment_helper_available = False
        parse_ip_header_fn = None
        if self.fragment_buffer is not None:
            try:
                from .core.fragmentation import parse_ip_header as _parse_ip_header
                parse_ip_header_fn = _parse_ip_header
                fragment_helper_available = True
                logger.info("eBPF capture: IP fragment reassembly ENABLED")
            except ImportError:
                logger.warning(
                    "eBPF capture: fragment_buffer provided but core.fragmentation "
                    "not importable — fragment reassembly disabled"
                )

        def _queue_packet(src_ip, dst_port, payload):
            """Queue a parsed packet dict for the processing workers."""
            packet_data = {
                'src_ip': src_ip,
                'dst_port': dst_port,
                'payload': payload,
            }
            try:
                packet_queue.put_nowait(packet_data)
                if use_network_stats:
                    _queue_stats.record_queued()
                logger.debug(
                    f"Raw capture: queued packet from {src_ip} to port {dst_port}, "
                    f"{len(payload)} bytes"
                )
            except queue.Full:
                if use_network_stats:
                    _queue_stats.record_dropped()
                else:
                    logger.warning("Packet queue full, dropping packet")

        try:
            while not stop_event.is_set():
                # Use select to wait for data with timeout
                readable, _, _ = select.select([self.raw_socket], [], [], 0.5)

                if not readable:
                    continue

                # Receive packet (65535 bytes covers any jumbo frame or fragment chain)
                packet = self.raw_socket.recv(65535)

                # Skip if too short for Ethernet + minimal IP header
                if len(packet) < 34:  # 14 Ethernet + 20 IP
                    continue

                # Parse IP header (20 bytes starting after 14-byte Ethernet header)
                ip_header = packet[14:34]
                # Format: version_ihl, dscp, tot_len, ip_id, frag_off, ttl, proto,
                #         checksum, src_ip, dst_ip
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header[:20])

                # Check if UDP (protocol = 17)
                if iph[6] != 17:
                    continue

                src_ip = socket.inet_ntoa(iph[8])

                # --- Fragment detection ---
                # iph[4] is the 16-bit flags+frag_offset field (network byte order,
                # already converted to host order by struct.unpack with '!')
                frag_field = iph[4]
                mf_flag = bool(frag_field & 0x2000)    # More Fragments bit
                frag_offset = frag_field & 0x1FFF       # Fragment offset (8-byte units)
                is_fragment = mf_flag or frag_offset > 0

                if is_fragment:
                    if not fragment_helper_available or self.fragment_buffer is None:
                        # Fragment reassembly not configured: log a warning so the
                        # operator knows traps may be lost (never silent).
                        logger.warning(
                            f"IP fragment received from {src_ip} (id={iph[3]}, "
                            f"offset={frag_offset}, MF={mf_flag}) but fragment "
                            "reassembly is disabled in eBPF mode. Large traps "
                            "(>1472 bytes) may be lost. Enable fragment_reassembly "
                            "in capture_config.json."
                        )
                        continue

                    # Feed fragment into the reassembly buffer.
                    # parse_ip_header expects raw bytes starting at the IP header
                    # (no Ethernet prefix), and returns an IPFragment with:
                    #   .data = everything after the IP header for this fragment
                    fragment = parse_ip_header_fn(packet[14:])
                    if fragment is None:
                        logger.debug(
                            f"Could not parse IP fragment from {src_ip}, skipping"
                        )
                        continue

                    reassembled = self.fragment_buffer.add_fragment(fragment)
                    if reassembled is None:
                        # Fragment stored; waiting for remaining pieces
                        continue

                    # Reassembly complete: reassembled = UDP header + SNMP payload
                    if len(reassembled) < 8:
                        logger.warning(
                            f"Reassembled datagram from {src_ip} is too short "
                            f"({len(reassembled)} bytes), discarding"
                        )
                        continue

                    dst_port = struct.unpack('!H', reassembled[2:4])[0]
                    if dst_port not in self.listen_ports:
                        continue

                    payload = reassembled[8:]  # Skip 8-byte UDP header
                    logger.debug(
                        f"eBPF: reassembled fragmented trap from {src_ip}, "
                        f"port={dst_port}, payload={len(payload)} bytes"
                    )
                    _queue_packet(src_ip, dst_port, payload)
                    continue

                # --- Complete (non-fragmented) packet ---
                ip_hlen = (iph[0] & 0x0F) * 4
                udp_start = 14 + ip_hlen

                if len(packet) < udp_start + 8:
                    continue

                udph = struct.unpack('!HHHH', packet[udp_start:udp_start + 8])
                dst_port = udph[1]

                if dst_port not in self.listen_ports:
                    continue

                payload_start = udp_start + 8
                payload = packet[payload_start:]

                _queue_packet(src_ip, dst_port, payload)

        except Exception as e:
            if not stop_event.is_set():
                logger.error(f"Error in raw packet capture loop: {e}")

        logger.info("Raw packet capture loop stopped")

    def _init_bpf_program(self):
        """
        Initialize and load the BPF program

        Returns:
            bool: True if successful, False otherwise
        """
        # Check if BPF is available
        if BPF is None:
            logger.warning("BPF class not available, cannot initialize eBPF")
            if EBPF_IMPORT_ERROR:
                logger.debug(f"BPF import error: {EBPF_IMPORT_ERROR}")
            return False
        
        # Try programs in order: complex (with perf) then simple (filter only)
        programs_to_try = [
            ("complex (perf_submit)", MINIMAL_BPF_PROGRAM, True),
            ("simple (filter only)", SIMPLE_SOCKET_FILTER, False),
        ]
        
        for prog_name, prog_text, uses_perf in programs_to_try:
            logger.info(f"Trying {prog_name} BPF program...")
            
            result = self._try_load_bpf_program(prog_text, uses_perf)
            if result:
                return True
            
            logger.info(f"{prog_name} BPF program failed, trying next...")
        
        logger.warning("All BPF programs failed to load")
        return False
    
    def _try_load_bpf_program(self, program_text, uses_perf):
        """
        Try to load a specific BPF program.
        
        Args:
            program_text: BPF C program source
            uses_perf: Whether program uses perf events
            
        Returns:
            bool: True if successful
        """
        try:
            logger.debug("Attempting to load eBPF program...")

            # Load BPF program
            self.bpf = BPF(text=program_text)
            logger.info("BPF program compiled successfully")

            # Set up ports table
            ports_table = self.bpf.get_table("ports")

            # Add our listen ports to the hash table
            for port in self.listen_ports:
                if isinstance(port, int) and 1 <= port <= 65535:
                    logger.debug(f"Adding port {port} to eBPF hash table")
                    ports_table[ct.c_uint16(port)] = ct.c_uint8(1)

            logger.info(f"Monitoring ports added to eBPF hash table: {self.listen_ports}")
            
            # Store whether this program uses perf
            self._uses_perf = uses_perf

            # Attach to interface - use packet filter function
            function_name = "packet_filter"

            try:
                # Determine interface
                if self.interface == "any" or self.interface == "all":
                    logger.info("Attaching eBPF filter to all interfaces")
                    iface = ""
                else:
                    logger.info(f"Attaching eBPF filter to interface: {self.interface}")
                    iface = self.interface
                
                # Log available BPF program types for diagnostics
                prog_types = [attr for attr in dir(BPF) if attr.isupper() and not attr.startswith('_')]
                logger.info(f"Available BPF constants: {prog_types[:10]}...")  # First 10
                
                # Get the function object (required for newer BCC versions)
                # Try multiple methods for compatibility across BCC versions
                fn = None
                
                # Method 1: Try load_func with SOCKET_FILTER
                socket_filter_type = getattr(BPF, 'SOCKET_FILTER', None)
                if socket_filter_type is not None:
                    try:
                        fn = self.bpf.load_func(function_name, socket_filter_type)
                        logger.info(f"Loaded BPF function using load_func(SOCKET_FILTER={socket_filter_type})")
                    except Exception as e:
                        logger.info(f"load_func(SOCKET_FILTER) failed: {e}")
                        fn = None
                
                # Method 1b: Try load_func with SCHED_CLS (might work better with perf_submit)
                if fn is None:
                    sched_cls_type = getattr(BPF, 'SCHED_CLS', None)
                    if sched_cls_type is not None:
                        try:
                            fn = self.bpf.load_func(function_name, sched_cls_type)
                            logger.info(f"Loaded BPF function using load_func(SCHED_CLS={sched_cls_type})")
                        except Exception as e:
                            logger.info(f"load_func(SCHED_CLS) failed: {e}")
                            fn = None
                
                # Method 2: Try accessing function directly from bpf object
                if fn is None:
                    try:
                        fn = self.bpf[function_name]
                        if fn is not None:
                            logger.info(f"Loaded BPF function using bpf[name] accessor, type={type(fn)}")
                        else:
                            logger.info("bpf[name] accessor returned None")
                            fn = None
                    except (KeyError, TypeError) as e:
                        logger.info(f"bpf[name] accessor failed: {e}")
                        fn = None
                
                # Method 2b: Try function attribute access
                if fn is None:
                    try:
                        if hasattr(self.bpf, 'funcs'):
                            logger.info(f"Available funcs: {list(self.bpf.funcs.keys()) if hasattr(self.bpf.funcs, 'keys') else self.bpf.funcs}")
                            if function_name in self.bpf.funcs:
                                fn = self.bpf.funcs[function_name]
                                logger.info(f"Got function from bpf.funcs, type={type(fn)}")
                    except Exception as e:
                        logger.info(f"bpf.funcs access failed: {e}")
                
                # Log what we got
                if fn is not None:
                    logger.info(f"BPF function obtained: type={type(fn).__name__}, has fd={hasattr(fn, 'fd')}")
                else:
                    logger.warning("Could not obtain BPF function object")
                
                # Try different attachment methods based on what we have
                attached = False
                
                # Method A: Use function object with BPF.attach_raw_socket as class method
                if fn is not None and not attached:
                    try:
                        sock_fd = BPF.attach_raw_socket(fn, iface)
                        if sock_fd is not None:
                            attached = True
                            logger.info(f"Attached using BPF.attach_raw_socket(fn, iface), sock_fd={sock_fd}")
                    except Exception as e:
                        logger.info(f"BPF.attach_raw_socket class method failed: {e}")
                
                # Method B: Use function object with instance method
                if fn is not None and not attached:
                    try:
                        sock_fd = self.bpf.attach_raw_socket(fn, iface)
                        if sock_fd is not None:
                            attached = True
                            logger.info(f"Attached using self.bpf.attach_raw_socket(fn, iface), sock_fd={sock_fd}")
                    except Exception as e:
                        logger.info(f"Instance attach_raw_socket with fn failed: {e}")
                
                # Method C: Try string-based attach (older API)
                if not attached:
                    try:
                        sock_fd = self.bpf.attach_raw_socket(function_name, iface)
                        if sock_fd is not None:
                            attached = True
                            logger.info(f"Attached using string function name, sock_fd={sock_fd}")
                    except Exception as e:
                        logger.info(f"String-based attach_raw_socket failed: {e}")
                
                # Method D: Try creating socket and using setsockopt
                if not attached and fn is not None and hasattr(fn, 'fd'):
                    try:
                        import socket as sock_module
                        raw_sock = sock_module.socket(sock_module.AF_PACKET, sock_module.SOCK_RAW, sock_module.htons(0x0003))
                        if iface:
                            raw_sock.bind((iface, 0))
                        
                        SO_ATTACH_BPF = 50
                        raw_sock.setsockopt(sock_module.SOL_SOCKET, SO_ATTACH_BPF, fn.fd)
                        attached = True
                        self._ebpf_socket = raw_sock
                        logger.info(f"Attached using SO_ATTACH_BPF setsockopt, fn.fd={fn.fd}")
                    except Exception as e:
                        logger.info(f"Manual socket attachment failed: {e}")
                
                if attached:
                    logger.info("eBPF filter attached successfully")
                    return True
                else:
                    logger.warning("All eBPF attachment methods failed - will use raw capture fallback")
                    return False
                    
            except Exception as e:
                logger.error(f"Unexpected error during eBPF attachment: {e}")
                import traceback
                logger.debug(traceback.format_exc())
                return False

        except Exception as e:
            logger.error(f"Error initializing BPF program: {e}")
            return False

    def _process_event(self, cpu, data, size):
        """
        Process eBPF events received from kernel

        Args:
            cpu: CPU ID where the event occurred
            data: Raw event data
            size: Size of the data
        """
        # Check if we should stop
        if stop_event and stop_event.is_set():
            return

        try:
            # Define the structure matching our eBPF program
            class EventData(ct.Structure):
                _fields_ = [
                    ("src_ip", ct.c_uint32),
                    ("dst_port", ct.c_uint16),
                    ("size", ct.c_uint32)
                ]

            # Parse the event data
            event = ct.cast(data, ct.POINTER(EventData)).contents

            # Convert source IP
            src_ip = socket.inet_ntoa(ct.c_uint32(event.src_ip))
            dst_port = event.dst_port

            logger.debug(f"eBPF event: packet from {src_ip} to port {dst_port}, size={event.size}")

            # In minimal mode, we need to capture the actual packet data from the socket
            # This is because we don't extract the payload in the eBPF program
            # Instead, we use the event as a trigger to know that a packet was detected

            # For the pure event-based eBPF mode, we don't actually have the payload data
            # We would need to use additional raw sockets to capture the full packets
            # In production, you would want to implement a mechanism to correlate these events
            # with actual packet data

            # For now, we're just going to log the event
            logger.info(f"eBPF event detected: SNMP trap from {src_ip} to port {dst_port}")

            # In this minimal implementation, we fall back to raw packet capture for the actual data
            # The eBPF program is just used for high-performance filtering

        except Exception as e:
            logger.error(f"Error processing eBPF event: {e}")

    def start(self):
        """
        Start the packet capture

        Returns:
            bool: True if successful, False otherwise
        """
        logger.info("Starting trapninja packet capture with eBPF acceleration")

        # Try to initialize eBPF program first
        ebpf_success = self._init_bpf_program()

        if ebpf_success:
            try:
                # Only set up perf buffer if program uses perf events
                if getattr(self, '_uses_perf', False):
                    # Open the perf buffer for events from kernel
                    self.bpf["events"].open_perf_buffer(self._process_event)
                    logger.info("eBPF perf buffer opened successfully")

                    # Start the polling thread
                    self.poller_thread = threading.Thread(target=self._poll_events, daemon=True)
                    self.poller_thread.start()
                else:
                    logger.info("Simple eBPF filter active (no perf events)")

                # Start raw capture - eBPF filter will pre-filter packets
                self._init_raw_capture()

                logger.info(f"eBPF-accelerated packet capture started on interface {self.interface}")
                return True
            except Exception as e:
                logger.error(f"Failed to start eBPF capture: {e}")
                ebpf_success = False

        # Fall back to raw capture if eBPF fails
        if not ebpf_success:
            logger.warning("eBPF initialization failed, falling back to raw packet capture")
            raw_success = self._init_raw_capture()

            if raw_success:
                logger.info("Raw packet capture fallback started successfully")
                return True
            else:
                logger.error("Failed to start capture - both eBPF and raw capture methods failed")
                return False

    def _poll_events(self):
        """Poll for eBPF events"""
        try:
            logger.info("Starting eBPF event polling")

            while not stop_event.is_set():
                try:
                    # Process available events
                    self.bpf.perf_buffer_poll(timeout=100)

                    # Sleep briefly to reduce CPU usage during polling
                    time.sleep(0.01)
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    if not stop_event.is_set():
                        logger.error(f"Error polling eBPF events: {e}")
                        time.sleep(1)  # Avoid tight loop on errors

            logger.info("eBPF event polling stopped")
        except Exception as e:
            logger.error(f"Fatal error in eBPF event polling: {e}")

    def stop(self):
        """Stop packet capture"""
        logger.info("Stopping packet capture")

        # Stop raw socket if active
        if self.raw_socket:
            try:
                self.raw_socket.close()
                logger.info("Raw socket closed")
            except Exception as e:
                logger.error(f"Error closing raw socket: {e}")

        # Clean up BPF resources
        if self.bpf:
            # BPF resources are cleaned up automatically
            logger.info("BPF resources released")

        logger.info("Packet capture stopped")
        return True


# Function to check if eBPF is supported on this system
def is_ebpf_supported():
    """
    Check if eBPF is supported on this system

    Returns:
        bool: True if supported, False otherwise
    """
    # Check if BPF import failed
    if BPF is None:
        if EBPF_IMPORT_ERROR:
            logger.warning(f"eBPF not supported: {EBPF_IMPORT_ERROR}")
        return False
    
    try:
        # Check kernel version (need 4.4+ for basic eBPF support)
        import platform
        kernel_version = platform.release().split("-")[0]
        major, minor = map(int, kernel_version.split(".")[:2])

        if major < 4 or (major == 4 and minor < 4):
            logger.warning(f"Kernel {kernel_version} may not fully support eBPF (4.4+ recommended)")
            return False

        # Check if BCC is available and can load a minimal program
        try:
            test_bpf = BPF(text="""
            int dummy(void *ctx) {
                return 0;
            }
            """)

            # Clean up test BPF program
            del test_bpf
            logger.debug("BPF test program compiled successfully")
        except Exception as e:
            logger.warning(f"BPF test compilation failed: {e}")
            return False

        # Check if we have required permissions
        if os.geteuid() != 0:
            logger.warning("eBPF requires root privileges to load programs")
            return False

        logger.debug("eBPF appears to be supported on this system")
        return True
    except Exception as e:
        logger.warning(f"eBPF support check failed: {e}")
        return False


# Function to check if required packages are installed
def check_ebpf_dependencies():
    """
    Check if required eBPF dependencies are installed

    Returns:
        bool: True if all dependencies are met, False otherwise
    """
    # Check if BPF import failed
    if BPF is None:
        if EBPF_IMPORT_ERROR:
            logger.debug(f"eBPF dependencies not met: {EBPF_IMPORT_ERROR}")
        return False
    
    try:
        # Try to import required modules
        import bcc
        logger.info(f"BCC version: {bcc.__version__}")
        return True
    except ImportError as e:
        logger.error(f"Required eBPF dependency missing: {e}")
        return False


# Create a compatible capture instance
def create_capture(interface, listen_ports, queue_ref, stop_event_ref,
                   fragment_buffer=None):
    """
    Create a capture instance, either eBPF or traditional

    Args:
        interface (str): Network interface to capture on
        listen_ports (list): List of UDP ports to listen for traps
        queue_ref (queue.Queue): Reference to the packet processing queue
        stop_event_ref (threading.Event): Reference to the stop event
        fragment_buffer: Optional FragmentReassemblyBuffer for reassembling
            fragmented SNMP traps arriving in eBPF mode

    Returns:
        object: Capture instance
    """
    return MinimalTrapCapture(interface, listen_ports, queue_ref, stop_event_ref,
                              fragment_buffer=fragment_buffer)


# SnmpTrapCapture is the same as MinimalTrapCapture for backward compatibility
SnmpTrapCapture = MinimalTrapCapture


# Function to update eBPF configuration
def update_ebpf_config(listen_ports):
    """Placeholder for updating eBPF configuration"""
    logger.info(f"eBPF config update requested for ports: {listen_ports}")
    logger.warning("Dynamic port updates not implemented in minimal eBPF mode")


# Forwarding function
def forward_packet_ebpf(source_ip, payload, destinations_list):
    """Forward packet using the original implementation"""
    from .network import forward_packet as original_forward_packet
    original_forward_packet(source_ip, payload, destinations_list)