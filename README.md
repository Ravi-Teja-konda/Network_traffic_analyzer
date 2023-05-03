# Network Traffic Analyzer

Network Traffic Analyzer is a Python-based tool that analyzes network traffic captured in PCAP files. It provides valuable insights into the communication between different IP addresses, the distribution of network protocols, and potential port scanning activities. The application aims to aid network administrators and security experts in identifying network-related issues and security vulnerabilities.

## Features

- Analyze network traffic from PCAP files
- Calculate total bandwidth used
- Display protocol distribution
- Identify top IP address communications
- Detect potential port scanning activities

## Future Enhancements

In the future, the Network Traffic Analyzer will include the following features:
- Plotting graphs w.r.t IP
- Calculating latency, packet loss, throughput, jitter, network utilization, and error rates

## Installation

1. Clone the repository:


2. Navigate to the project directory:
cd network-traffic-analyzer

3. Install the required dependencies:
pip install -r requirements.txt


## Usage

To analyze a PCAP file, run the following command:

python Network_traffic_analyzer.py <path_to_pcap_file> <port_scan_threshold>


Replace `<path_to_pcap_file>` with the path to your PCAP file, and `<port_scan_threshold>` with the desired threshold for detecting port scanning activities.

## Contributing

We welcome contributions from the community! If you'd like to contribute, please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

- [Scapy](https://github.com/secdev/scapy) for packet processing capabilities
- [Pandas](https://github.com/pandas-dev/pandas) for data manipulation and analysis
- [Matplotlib](https://github.com/matplotlib/matplotlib) for creating graphs and visualizations
