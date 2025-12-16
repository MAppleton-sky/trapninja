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

try:
    # Add BCC installation path for cmake-built installations
    # Note: We prioritize package manager paths over /usr/local to avoid
    # importing the wrong 'bcc' package (Will Sheffler's package)
    BCC_PATHS = [
        '/usr/lib/python3.9/site-packages',        # Package manager (preferred)
        '/usr/lib64/python3.9/site-packages',      # Package manager 64-bit
        '/usr/lib/python{}.{}/site-packages'.format(
            sys.version_info.major, sys.version_info.minor
        ),
        '/usr/lib64/python{}.{}/site-packages'.format(
            sys.version_info.major, sys.version_info.minor
        ),
        '/usr/local/lib/python3.9/site-packages',  # CMake/source build (last)
        '/usr/local/lib/python{}.{}/site-packages'.format(
            sys.version_info.major, sys.version_info.minor
        ),
    ]

    # Verify paths contain real BCC before adding
    for path in BCC_PATHS:
        bcc_path = os.path.join(path, 'bcc')
        if os.path.exists(bcc_path):
            # Quick check: Real BCC has larger __init__.py or .so files
            try:
                init_file = os.path.join(bcc_path, '__init__.py')
                if os.path.exists(init_file):
                    # Skip if it's the wrong 'bcc' package (Will Sheffler's)
                    if os.path.getsize(init_file) < 300:
                        with open(init_file, 'r') as f:
                            if 'willsheffler' in f.read().lower():
                                continue  # Skip this path
                
                # Check for compiled extensions or other real BCC indicators
                contents = os.listdir(bcc_path)
                has_real_bcc = any(f.endswith('.so') for f in contents) or 'libbcc.py' in contents
                
                if has_real_bcc or os.path.getsize(init_file) > 500:
                    if path not in sys.path:
                        sys.path.insert(0, path)
            except:
                pass

    # Now import BCC
    from bcc import BPF as _BPF
    BPF = _BPF
    logger.debug("BCC imported successfully")
except ImportError as e:
    EBPF_IMPORT_ERROR = f"BCC not installed: {e}"
    logger.debug(f"BCC import failed: {e}")
except AttributeError as e:
    EBPF_IMPORT_ERROR = f"BCC version mismatch with system libraries: {e}"
    logger.warning(f"BCC import failed due to version mismatch: {e}")
except Exception as e:
    EBPF_IMPORT_ERROR = f"BCC import error: {e}"
    logger.warning(f"Unexpected BCC import error: {e}")

# Define extremely minimal BPF program - avoiding all complex features
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

# Packet queue for communication with existing TrapNinja processing logic
packet_queue = None

# Stop event for graceful shutdown
stop_event = None


class MinimalTrapCapture:
    """Minimal eBPF-based SNMP trap capture with fallback mechanisms"""

    def __init__(self, interface, listen_ports, queue_ref, stop_event_ref):
        """
        Initialize the eBPF trap capture

        Args:
            interface (str): Network interface to capture on
            listen_ports (list): List of UDP ports to listen for traps
            queue_ref (queue.Queue): Reference to the packet processing queue
            stop_event_ref (threading.Event): Reference to the stop event
        """
        self.interface = interface
        self.listen_ports = listen_ports
        self.bpf = None

        # Store references to existing structures
        global packet_queue, stop_event
        packet_queue = queue_ref
        stop_event = stop_event_ref

        # For capturing raw packets as fallback
        self.raw_socket = None
        self.capture_thread = None

        logger.debug(f"MinimalTrapCapture initialized with interface={interface}, ports={listen_ports}")

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

        try:
            while not stop_event.is_set():
                # Use select to wait for data with timeout
                readable, _, _ = select.select([self.raw_socket], [], [], 0.5)

                if not readable:
                    continue

                # Receive packet
                packet = self.raw_socket.recv(4096)

                # Skip if too short
                if len(packet) < 34:  # Ethernet + IP header + part of UDP
                    continue

                # Parse IP header
                ip_header = packet[14:34]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header[:20])

                # Check if UDP (protocol = 17)
                if iph[6] != 17:
                    continue

                # Get source IP
                src_ip = socket.inet_ntoa(iph[8])

                # Parse UDP header
                udp_start = 14 + (iph[0] & 0x0F) * 4
                udph = struct.unpack('!HHHH', packet[udp_start:udp_start + 8])
                dst_port = udph[1]

                # Check if destination port is one we're listening for
                if dst_port not in self.listen_ports:
                    continue

                # Get UDP payload
                payload_start = udp_start + 8
                payload = packet[payload_start:]

                # Create packet data structure
                packet_data = {
                    'src_ip': src_ip,
                    'dst_port': dst_port,
                    'payload': payload
                }

                # Queue packet for processing
                try:
                    if packet_queue and not packet_queue.full():
                        packet_queue.put(packet_data, block=False)
                        logger.debug(
                            f"Raw capture: queued packet from {src_ip} to port {dst_port}, {len(payload)} bytes")
                    else:
                        logger.warning("Packet queue full or not available, dropping packet")
                except Exception as e:
                    logger.error(f"Error queuing raw captured packet: {e}")

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
        
        try:
            logger.debug("Attempting to load minimal eBPF program...")

            # Load BPF program
            self.bpf = BPF(text=MINIMAL_BPF_PROGRAM)
            logger.debug("Successfully loaded minimal eBPF program")

            # Set up ports table
            ports_table = self.bpf.get_table("ports")

            # Add our listen ports to the hash table
            for port in self.listen_ports:
                if isinstance(port, int) and 1 <= port <= 65535:
                    logger.debug(f"Adding port {port} to eBPF hash table")
                    ports_table[ct.c_uint16(port)] = ct.c_uint8(1)

            logger.info(f"Monitoring ports added to eBPF hash table: {self.listen_ports}")

            # Attach to interface - use packet filter function
            function_name = "packet_filter"

            try:
                if self.interface == "any" or self.interface == "all":
                    logger.info("Attaching eBPF filter to all interfaces")
                    self.bpf.attach_raw_socket(function_name, "")
                else:
                    logger.info(f"Attaching eBPF filter to interface: {self.interface}")
                    self.bpf.attach_raw_socket(function_name, self.interface)

                logger.info("eBPF filter attached successfully")
                return True
            except Exception as e:
                logger.error(f"Failed to attach eBPF filter: {e}")
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
                # Open the perf buffer for events from kernel
                self.bpf["events"].open_perf_buffer(self._process_event)
                logger.info("eBPF perf buffer opened successfully")

                # Start the polling thread
                self.poller_thread = threading.Thread(target=self._poll_events, daemon=True)
                self.poller_thread.start()

                # Also start raw capture as we need to actually get the packets
                self._init_raw_capture()

                logger.info(f"eBPF-based packet capture started on interface {self.interface}")
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
def create_capture(interface, listen_ports, queue_ref, stop_event_ref):
    """
    Create a capture instance, either eBPF or traditional

    Args:
        interface (str): Network interface to capture on
        listen_ports (list): List of UDP ports to listen for traps
        queue_ref (queue.Queue): Reference to the packet processing queue
        stop_event_ref (threading.Event): Reference to the stop event

    Returns:
        object: Capture instance
    """
    return MinimalTrapCapture(interface, listen_ports, queue_ref, stop_event_ref)


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