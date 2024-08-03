# MIT License
# 
# Copyright (c) 2024 cemaxecuter
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import ssl
import socket
import signal
import logging
import argparse
import datetime
import requests
import time
from lxml import etree
from typing import Optional
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.serialization.pkcs12

# Setup logging
logger = logging.getLogger(__name__)

class Aircraft:
    """A class representing an aircraft and its telemetry data."""

    def __init__(self, hex_id, lat, lon, alt_baro, alt_geom, speed, track, squawk, callsign):
        # Initialize aircraft properties
        self.hex_id = hex_id
        self.lat = lat
        self.lon = lon
        self.alt = alt_baro  # Use alt_baro as fallback
        self.alt_geom = alt_geom  # Use alt_geom if available
        self.speed = speed
        self.track = track
        self.squawk = squawk
        self.callsign = callsign
        self.last_update_time = time.time()

    def to_cot_xml(self) -> bytes:
        """Convert the aircraft's telemetry data to a Cursor-on-Target (CoT) XML message."""
        event = etree.Element('event')
        event.set('version', '2.0')
        event.set('uid', f"aircraft-{self.hex_id}")  # Ensure this UID is stable and consistent
        event.set('type', 'a-f-G-U-C')  # Example type for an aircraft
        event.set('time', datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.995Z'))
        event.set('start', datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.995Z'))
        event.set('stale', (datetime.datetime.utcnow() + datetime.timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%S.995Z'))  # Extended stale time
        event.set('how', 'm-g')

        # Use alt_geom for elevation (hae) if available, otherwise fallback to alt_baro
        hae_value = self.alt_geom if self.alt_geom is not None else self.alt

        point = etree.SubElement(event, 'point')
        point.set('lat', str(self.lat))
        point.set('lon', str(self.lon))
        point.set('hae', str(hae_value))
        point.set('ce', '9999999.0')
        point.set('le', '9999999.0')

        detail = etree.SubElement(event, 'detail')

        contact = etree.SubElement(detail, 'contact')
        contact.set('endpoint', '')
        contact.set('phone', '')
        contact.set('callsign', self.callsign)

        # Add track information
        track = etree.SubElement(detail, 'track')
        track.set('course', str(self.track))
        track.set('speed', str(self.speed))

        remarks = etree.SubElement(detail, 'remarks')
        remarks.text = f"Speed: {self.speed} knots, Track: {self.track}°, Squawk: {self.squawk}"

        color = etree.SubElement(detail, 'color')
        color.set('argb', '-256')  # Default color, may show as a standard dot in ATAK

        usericon = etree.SubElement(detail, 'usericon')
        usericon.set('iconsetpath', 'Civ/Air/Cessna.png')  # Path for a small civilian aircraft icon

        return etree.tostring(event, pretty_print=True, xml_declaration=True, encoding='UTF-8')


class TAKClient:
    """A client for connecting to a TAK server using TLS and sending CoT messages."""

    def __init__(self, tak_host: str, tak_port: int, tak_tls_context: Optional[ssl.SSLContext]):
        # Initialize TAK server connection parameters
        self.tak_host = tak_host
        self.tak_port = tak_port
        self.tak_tls_context = tak_tls_context
        self.sock = None

    def connect(self):
        """Establish a connection to the TAK server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.tak_tls_context:
                self.sock = self.tak_tls_context.wrap_socket(self.sock)
            self.sock.connect((self.tak_host, self.tak_port))
            logger.debug("Connected to TAK server")
        except Exception as e:
            logger.error(f"Error connecting to TAK server: {e}")

    def send(self, cot_xml: bytes):
        """Send a CoT XML message to the TAK server."""
        try:
            if self.sock is None:
                self.connect()
            self.sock.send(cot_xml)
            logger.debug(f"Sent CoT to TAK server: {cot_xml}")
        except Exception as e:
            logger.error(f"Error sending to TAK server: {e}")
            self.sock = None  # Force reconnect on next send

    def close(self):
        """Close the connection to the TAK server."""
        if self.sock:
            self.sock.close()
            self.sock = None
            logger.debug("Closed connection to TAK server")


def send_to_tak_udp(cot_xml: bytes, tak_host: str, tak_port: int):
    """Send a CoT XML message to the TAK server via UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(cot_xml, (tak_host, tak_port))
        sock.close()
        logger.debug(f"Sent CoT to TAK server: {cot_xml}")
    except Exception as e:
        logger.error(f"Error sending to TAK server: {e}")


def send_to_tak_udp_multicast(cot_xml: bytes, multicast_address: str, multicast_port: int):
    """Send a CoT XML message to a multicast address via UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(cot_xml, (multicast_address, multicast_port))
        sock.close()
        logger.debug(f"Sent CoT to multicast address: {cot_xml}")
    except Exception as e:
        logger.error(f"Error sending to multicast address: {e}")


def fetch_tar1090_data(tar1090_url: str):
    """Fetch JSON data from the tar1090 instance."""
    try:
        logger.debug(f"Fetching data from tar1090 URL: {tar1090_url}")
        response = requests.get(tar1090_url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Error fetching data from tar1090: {e}")
        return None


def tar1090_to_cot(tar1090_url, tak_host=None, tak_port=None, tak_tls_context=None, multicast_address=None, multicast_port=None, enable_multicast=False, poll_period=10.0):
    """
    Convert tar1090 JSON data to CoT messages and send to a TAK server or multicast address.

    Args:
        tar1090_url (str): URL to fetch tar1090 JSON data.
        tak_host (str): TAK server hostname or IP address (optional).
        tak_port (int): TAK server port (optional).
        tak_tls_context (ssl.SSLContext): TLS context for secure connection to TAK server (optional).
        multicast_address (str): Multicast address for sending CoT messages (optional).
        multicast_port (int): Multicast port for sending CoT messages (optional).
        enable_multicast (bool): Flag to enable sending to multicast address.
        poll_period (float): Poll period for fetching tar1090 data in seconds.
    """
    aircrafts = {}  # Store aircrafts by their unique hex_id
    tak_client = None

    # Set default multicast address and port if none are provided
    if not multicast_address:
        multicast_address = "239.2.3.1"  # Default multicast address
    if not multicast_port:
        multicast_port = 6969  # Default multicast port

    # Initialize TAK client if TAK server details are provided
    if tak_host and tak_port:
        if tak_tls_context:
            tak_client = TAKClient(tak_host, tak_port, tak_tls_context)
    else:
        # No TAK server details, default to multicast
        enable_multicast = True

    def signal_handler(sig, frame):
        """Handle signal interruptions for graceful shutdown."""
        print("Interrupted by user")
        if tak_client:
            tak_client.close()
        print("Cleaned up resources")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            # Fetch the latest aircraft data from tar1090
            data = fetch_tar1090_data(tar1090_url)
            if not data:
                time.sleep(poll_period)
                continue

            for aircraft in data.get('aircraft', []):
                # Extract relevant aircraft data
                hex_id = aircraft.get('hex', 'unknown')
                lat = aircraft.get('lat', None)
                lon = aircraft.get('lon', None)
                alt_baro = aircraft.get('alt_baro', 0)
                alt_geom = aircraft.get('alt_geom', None)
                speed = aircraft.get('gs', 0)
                track = aircraft.get('track', 0)
                squawk = aircraft.get('squawk', '')
                callsign = aircraft.get('flight', '').strip()

                # Only process aircraft with valid latitude and longitude
                if lat is not None and lon is not None:
                    if hex_id not in aircrafts:
                        # Create a new Aircraft object if it doesn't already exist
                        aircrafts[hex_id] = Aircraft(hex_id, lat, lon, alt_baro, alt_geom, speed, track, squawk, callsign)

                    aircraft_obj = aircrafts[hex_id]
                    aircraft_obj.last_update_time = time.time()

                    # Convert aircraft data to CoT XML
                    cot_xml = aircraft_obj.to_cot_xml()

                    # Send the CoT message to the TAK server if details are provided
                    if tak_host and tak_port:
                        if tak_tls_context:
                            if tak_client:
                                tak_client.send(cot_xml)
                        else:
                            send_to_tak_udp(cot_xml, tak_host, tak_port)

                    # Optionally send the CoT message to a multicast address
                    if enable_multicast:
                        send_to_tak_udp_multicast(cot_xml, multicast_address, multicast_port)

            time.sleep(poll_period)

    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="tar1090 to CoT converter.")
    parser.add_argument("--tar1090-url", default="http://127.0.0.1:8078/data/aircraft.json", help="tar1090 JSON data URL")
    parser.add_argument("--tak-host", type=str, help="TAK server hostname or IP address (optional)")
    parser.add_argument("--tak-port", type=int, help="TAK server port (optional)")
    parser.add_argument("--tak-tls-p12", type=str, help="Path to TAK server TLS PKCS#12 file (optional)")
    parser.add_argument("--tak-tls-p12-pass", type=str, help="Password for TAK server TLS PKCS#12 file (optional)")
    parser.add_argument("--tak-tls-skip-verify", action="store_true", help="(UNSAFE) Disable TLS server verification")
    parser.add_argument("--tak-multicast-addr", type=str, default="239.2.3.1", help="ATAK multicast address (optional)")
    parser.add_argument("--tak-multicast-port", type=int, default=6969, help="ATAK multicast port (optional)")
    parser.add_argument("--enable-multicast", action="store_true", help="Enable sending to multicast address")
    parser.add_argument("--poll-period", type=float, default=10.0, help="Poll period for fetching tar1090 data (seconds)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    tak_tls_context = None
    if args.tak_tls_p12:
        try:
            with open(args.tak_tls_p12, 'rb') as p12_file:
                p12_data = p12_file.read()
        except OSError as err:
            logger.critical("Failed to read TAK server TLS PKCS#12 file: %s.", err)
            exit(1)

        p12_pass = None
        pem_encryption = cryptography.hazmat.primitives.serialization.NoEncryption()
        if args.tak_tls_p12_pass:
            p12_pass = args.tak_tls_p12_pass.encode()
            pem_encryption = cryptography.hazmat.primitives.serialization.BestAvailableEncryption(p12_pass)

        try:
            key, cert, more_certs = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(p12_data, p12_pass)
        except Exception as err:
            logger.critical("Failed to load TAK server TLS PKCS#12: %s.", err)
            exit(1)

        key_bytes = key.private_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM,
                                      cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
                                      pem_encryption)
        cert_bytes = cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
        ca_bytes = b"".join(cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM) for cert in more_certs)

        with tempfile.NamedTemporaryFile(delete=False) as key_file, \
                tempfile.NamedTemporaryFile(delete=False) as cert_file, \
                tempfile.NamedTemporaryFile(delete=False) as ca_file:
            key_file.write(key_bytes)
            cert_file.write(cert_bytes)
            ca_file.write(ca_bytes)

        tak_tls_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        tak_tls_context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name, password=p12_pass)
        if len(ca_bytes) > 0:
            tak_tls_context.load_verify_locations(cafile=ca_file.name)
        if args.tak_tls_skip_verify:
            tak_tls_context.check_hostname = False
            tak_tls_context.verify_mode = ssl.VerifyMode.CERT_NONE

    tar1090_to_cot(args.tar1090_url, args.tak_host, args.tak_port, tak_tls_context, args.tak_multicast_addr, args.tak_multicast_port, args.enable_multicast, args.poll_period)
