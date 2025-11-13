#!/usr/bin/env python3
"""
TrapNinja Network Module - Fixed Version

Handles UDP socket operations and network listeners with improved
performance for high-volume trap processing and fixes thread pool issues.
"""
import socket
import logging
import threading
import queue
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from scapy.all import send, get_if_list, IP, UDP

from .config import stop_event, LISTEN_PORTS, INTERFACE

# Get logger instance
logger = logging.getLogger("trapninja")

# Sockets for UDP listeners
udp_sockets = {}

# Thread pool for more efficient thread management - lazily initialized
udp_thread_pool = None
udp_threads = {}

# Thread-safe queue for packet processing
packet_queue = queue.Queue(maxsize=10000)  # Limit to prevent memory issues


# Create a packet buffer pool to reduce memory allocations
class PacketPool:
    def __init__(self, max_size=1000):
        self.pool = deque(maxlen=max_size)
        self.max_size = max_size

    def get(self):
        """Get a buffer from the pool or create a new one if empty"""
        try:
            return self.pool.popleft()
        except IndexError:
            return bytearray(4096)  # Default buffer size for UDP packets

    def put(self, buffer):
        """Return a buffer to the pool for reuse"""
        if len(self.pool) < self.max_size:
            self.pool.append(buffer)


# Initialize the global packet pool
packet_pool = PacketPool()

# Flag to track if eBPF mode is active
ebpf_mode_active = False


def init_thread_pool():
    """Initialize the thread pool if not already done"""
    global udp_thread_pool
    if udp_thread_pool is None:
        logger.debug("Initializing UDP thread pool")
        udp_thread_pool = ThreadPoolExecutor(max_workers=10)
        return True
    return False


def start_udp_listener(port):
    """
    Start a UDP socket listener for a specific port using thread pool
    for improved efficiency

    Args:
        port (int): UDP port number to listen on

    Returns:
        bool: True if successful, False otherwise
    """
    global udp_sockets, udp_threads, udp_thread_pool, ebpf_mode_active

    # If eBPF mode is active, UDP socket listeners are not needed
    if ebpf_mode_active:
        logger.debug(f"eBPF mode active - UDP socket listener for port {port} not needed")
        return True

    # Initialize thread pool if not already done
    init_thread_pool()

    # Skip if we already have a socket for this port
    if port in udp_sockets and udp_sockets[port] is not None:
        return True

    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Set socket options to reuse address
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Set buffer size for high-volume traffic
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16777216)  # 16MB buffer

        # Try to bind to the listening port
        try:
            # Bind to all interfaces on the specified port
            sock.bind(('0.0.0.0', port))
            logger.info(f"UDP listener bound successfully to port {port}")

            # Store socket in dictionary
            udp_sockets[port] = sock

            # Submit to thread pool instead of creating new threads
            try:
                future = udp_thread_pool.submit(udp_receive_loop, sock, port)
                udp_threads[port] = future
            except RuntimeError as e:
                if "cannot schedule new futures" in str(e):
                    logger.warning("Thread pool shutdown, reinitializing")
                    # Reinitialize thread pool
                    udp_thread_pool = ThreadPoolExecutor(max_workers=10)
                    future = udp_thread_pool.submit(udp_receive_loop, sock, port)
                    udp_threads[port] = future
                else:
                    raise

            return True

        except socket.error as e:
            # If binding fails (e.g., port already in use), log but continue
            # Scapy will still capture packets via libpcap
            logger.warning(f"Could not bind to port {port}: {e}")
            logger.warning("Another process might be listening on this port already.")
            logger.warning("TrapNinja will still capture and forward packets using libpcap.")
            return False

    except Exception as e:
        logger.error(f"Error setting up UDP listener on port {port}: {e}")
        return False


def set_ebpf_mode(active):
    """
    Set whether eBPF mode is active. This affects UDP socket listener behavior.

    Args:
        active (bool): Whether eBPF mode is active
    """
    global ebpf_mode_active
    ebpf_mode_active = active
    logger.info(f"eBPF mode {'activated' if active else 'deactivated'}")


def start_all_udp_listeners():
    """
    Start UDP socket listeners for all configured ports

    Returns:
        bool: True if all listeners started, False if any failed
    """
    global ebpf_mode_active

    # If eBPF mode is active, UDP socket listeners are not needed
    if ebpf_mode_active:
        logger.info("eBPF mode active - UDP socket listeners not needed")
        return True

    success = True
    for port in LISTEN_PORTS:
        if not start_udp_listener(port):
            success = False
    return success


def restart_udp_listeners():
    """
    Restart all UDP listeners when configuration changes

    Returns:
        bool: True if successful, False otherwise
    """
    global ebpf_mode_active

    # If eBPF mode is active, no need to restart UDP listeners
    if ebpf_mode_active:
        logger.info("eBPF mode active - no need to restart UDP listeners")
        # May need to update eBPF configuration instead
        try:
            # This would be implemented in the eBPF module
            from .ebpf import update_ebpf_config
            update_ebpf_config(LISTEN_PORTS)
        except (ImportError, AttributeError):
            # eBPF module might not be available or doesn't have this function
            pass
        return True

    cleanup_udp_sockets()
    return start_all_udp_listeners()


def udp_receive_loop(sock, port):
    """
    Receive loop for a UDP socket on a specific port

    Args:
        sock (socket): Socket object to receive from
        port (int): Port number being listened on
    """
    global stop_event

    logger.info(f"UDP receive loop started for port {port}")

    if not sock:
        logger.error(f"UDP socket for port {port} not initialized")
        return

    # Set a timeout so we can check for stop_event periodically
    sock.settimeout(1.0)

    while not stop_event.is_set():
        try:
            # Get a buffer from the pool
            buffer = packet_pool.get()

            # Use the buffer for receiving data
            data, addr = sock.recvfrom_into(buffer, len(buffer))

            if data > 0:
                # Create a copy of just the data we received
                packet_data = {
                    'src_ip': addr[0],
                    'dst_port': port,
                    'payload': bytes(buffer[:data])
                }

                # Try to put in queue, but don't block if full
                try:
                    packet_queue.put(packet_data, block=False)
                    logger.debug(f"Queued {data} bytes from {addr[0]}:{addr[1]} on port {port}")
                except queue.Full:
                    logger.warning("Packet processing queue full, dropping packet")

                # Return buffer to the pool
                packet_pool.put(buffer)
        except socket.timeout:
            # This is expected due to the timeout we set
            continue
        except Exception as e:
            if not stop_event.is_set():
                logger.error(f"Error in UDP receive loop for port {port}: {e}")
            break

    logger.info(f"UDP receive loop stopped for port {port}")


def cleanup_udp_sockets():
    """
    Clean up all UDP sockets and threads on shutdown
    """
    global udp_sockets, udp_threads, udp_thread_pool, ebpf_mode_active

    # If eBPF mode is active, there should be no UDP sockets to clean up
    if ebpf_mode_active:
        logger.debug("eBPF mode active - no UDP sockets to clean up")
        return

    # Cancel all threads and close sockets
    for port, future in list(udp_threads.items()):
        if future is not None:
            future.cancel()

    for port, sock in list(udp_sockets.items()):
        if sock:
            try:
                sock.close()
                logger.info(f"UDP socket for port {port} closed")
            except Exception as e:
                logger.error(f"Error closing UDP socket for port {port}: {e}")
            udp_sockets[port] = None

    # Clear the dictionaries
    udp_sockets.clear()
    udp_threads.clear()

    # Shutdown thread pool
    if udp_thread_pool is not None:
        try:
            logger.debug("Shutting down UDP thread pool")
            udp_thread_pool.shutdown(wait=False)
        except Exception as e:
            logger.error(f"Error shutting down thread pool: {e}")


def forward_packet(source_ip, payload, destinations_list):
    """
    Forward packet to specified destinations with template reuse
    for improved efficiency

    Args:
        source_ip (str): Source IP to spoof
        payload (bytes): UDP payload to forward
        destinations_list (list): List of (ip, port) tuples to forward to
    """
    from .config import INTERFACE, destinations as global_destinations

    # Debug check for destinations - this directly checks the global config
    logger.debug(f"Config module destinations: {global_destinations}")
    logger.debug(f"Received destinations_list: {destinations_list}")

    # If destinations_list is empty but global_destinations isn't, use global_destinations
    if not destinations_list and global_destinations:
        logger.warning("Empty destinations_list provided, using global destinations instead")
        destinations_list = global_destinations

    if not destinations_list:
        logger.warning("No destinations configured for forwarding")
        return

    logger.debug(f"Attempting to forward packet from {source_ip} to {len(destinations_list)} destination(s)")
    logger.debug(f"Payload size: {len(payload)} bytes")

    # Check if running as root (required for raw sockets)
    import os
    is_root = os.geteuid() == 0
    if not is_root:
        logger.warning("Not running as root. Raw packet operations may fail due to insufficient permissions.")

    # Create template packet just once
    template_packet = IP(src=source_ip) / UDP(sport=162)

    # Reuse the template for each destination
    for dst_ip, dst_port in destinations_list:
        try:
            # Update the destination fields only
            template_packet[IP].dst = dst_ip
            template_packet[UDP].dport = dst_port

            # Complete packet only once the template is set up
            spoofed_packet = template_packet / payload

            # Try sending with specified interface first
            try:
                available_interfaces = get_if_list()
                if INTERFACE in available_interfaces:
                    logger.debug(f"Sending packet through interface {INTERFACE}")
                    send(spoofed_packet, verbose=False, iface=INTERFACE)
                else:
                    logger.warning(f"Interface {INTERFACE} not found, letting scapy choose interface")
                    send(spoofed_packet, verbose=False)
            except Exception as e:
                logger.warning(f"Error sending with specified interface: {e}")
                logger.warning("Trying to send without specifying interface")
                # Fall back to letting scapy choose the interface
                send(spoofed_packet, verbose=False)

            logger.info(f"Trap forwarded to {dst_ip}:{dst_port} (spoofed from {source_ip})")
        except OSError as e:
            if "Operation not permitted" in str(e):
                logger.error(f"Permission denied when sending packet to {dst_ip}:{dst_port}. Are you running as root?")
            else:
                logger.error(f"Network error forwarding packet to {dst_ip}:{dst_port}: {e}")
        except Exception as e:
            logger.error(f"Failed to forward packet to {dst_ip}:{dst_port}: {e}")


def packet_processing_worker():
    """
    Worker that processes packets from the queue
    This separates capture from processing for better performance
    """
    from .snmp import process_captured_packet

    while not stop_event.is_set():
        try:
            # Get packet with timeout to allow checking stop_event
            packet_data = packet_queue.get(timeout=1.0)
            process_captured_packet(packet_data)
            packet_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error in packet processing worker: {e}")


def start_packet_processors(num_workers=4):
    """
    Start multiple packet processing workers for parallel processing

    Args:
        num_workers (int): Number of worker threads to start

    Returns:
        list: List of worker thread objects
    """
    workers = []
    for _ in range(num_workers):
        worker = threading.Thread(target=packet_processing_worker, daemon=True)
        worker.start()
        workers.append(worker)
    return workers


def forward_trap(packet):
    """
    Modified packet capture function that queues packets for processing
    instead of processing immediately

    Args:
        packet: Scapy packet from sniff function
    """
    try:
        # Only queue if we have IP and UDP layers
        if packet.haslayer(IP) and packet.haslayer(UDP):
            # Check if destination port is one we're listening on (quick check)
            if packet[UDP].dport in LISTEN_PORTS:
                # Copy only what we need to reduce memory usage
                packet_data = {
                    'src_ip': packet[IP].src,
                    'dst_port': packet[UDP].dport,
                    'payload': bytes(packet[UDP].payload)
                }
                # Try to put in queue, but don't block if full
                try:
                    packet_queue.put(packet_data, block=False)
                except queue.Full:
                    logger.warning("Packet processing queue full, dropping packet")
    except Exception as e:
        logger.error(f"Error queuing packet: {e}")