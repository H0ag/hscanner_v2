# HScanner v2 Documentation

HScanner is a Python-based tool designed to scan IP addresses within a network, identify active hosts, and optionally scan for open ports. This tool is highly customizable and provides detailed, user-friendly output.

## Features

1. **Network Scanning**:

   - Detects active hosts using ICMP (ping) or ARP requests.
   - Supports scanning custom IP ranges or networks.

2. **Port Scanning**:

   - Checks for open TCP ports on identified hosts.

3. **Dynamic IP Generation**:

   - Generates IP ranges based on subnet masks or user-defined ranges.

4. **Real-Time Updates**:

   - Displays scan progress and results in a formatted table using the `rich` library.

5. **Platform-Specific Utilities**:

   - Clears ARP tables on Linux, MacOS, and Windows systems.

6. **Command-Line Interface (CLI)**:

   - Flexible argument options for different scanning modes and configurations.

## Installation

### Prerequisites

- Python 3.6 or higher
- Required libraries:
  ```bash
  pip install termcolor netifaces scapy rich
  ```

### Clone the Repository

```bash
git clone https://github.com/h0ag/hscanner_v2.git
cd hscanner_v2
```

## Usage

Run the script using:

```bash
python3 hscanner.py [OPTIONS]
```

### CLI Options

| Option            | Description                                                                                           |
| ----------------- | ----------------------------------------------------------------------------------------------------- |
| `-t, --timeout`   | Set the timeout in seconds for ping tests (default: 0.2).                                             |
| `-p, --ports`     | Enable port scanning on detected hosts.                                                               |
| `--ip`            | Scan open ports on a specific IP address.                                                             |
| `--flood, -f`     | Perform a faster scan using ping flooding.                                                            |
| `--network, -n`   | Scan a custom network by providing an IP address and subnet mask (e.g., `192.168.1.0 255.255.255.0`). |
| `--arp`           | Scan hosts using ARP requests (requires root privileges).                                             |
| `--range, -r`     | Scan a range of IP addresses (e.g., `192.168.1.1 192.168.1.255`).                                     |
| `--showdown, -sd` | Display IPs that are down (must be used with `--range`).                                              |

## Examples

1. **Basic Ping Scan**:

   ```bash
   python3 hscanner.py -t 0.5 --range 192.168.1.1 192.168.1.10
   ```

2. **ARP Scan**:

   ```bash
   sudo python3 hscanner.py --arp
   ```

3. **Network Scan with Port Detection**:

   ```bash
   python3 hscanner.py --network 192.168.1.0 255.255.255.0 -p
   ```

## Output

HScanner provides real-time updates using tables to display:

- IP addresses being scanned
- State (`Up` or `Down`)
- Response success rate

### Example Output for range arguments

```
Scanning network...
+------------------+-------+---------------+
| IP Address       | State | Success Rate  |
+------------------+-------+---------------+
| 192.168.1.1      | Up    | 100.00%       |
| 192.168.1.2      | Down  | 0.00%         |
+------------------+-------+---------------+
```

## Technical Details

### Key Functions

#### `get_local_ip()`

Retrieves the local IP address and subnet mask of the host.

#### `convert_decimal_to_binary(ip)`

Converts a decimal IP address to its binary representation.

#### `ping_ip(ip, timeout)`

Sends an ICMP echo request to an IP address and measures the response time.

#### `clear_arp_table()`

Clears the ARP table on the host system, supporting Linux, MacOS, and Windows.

#### `generateIPs(network_subnetmask, network, availIPs, scanrange)`

Generates a list of IP addresses based on the provided subnet mask or range.

#### `IPScanner_range(range, timeout)`

Scans a range of IP addresses for activity and displays the results in real-time.

#### `arp(target_ip)`

Uses ARP requests to identify active hosts on a network (requires root).

## Limitations

- Root privileges are required for ARP scans.
- Scanning large networks or ranges may be time-consuming.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


---
**Made by [Hoag](https://github.com/h0ag).**