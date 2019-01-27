- TCPRedir captures TCP incoming traffic on any network interface and, based on the TCP destination port (inbound)
diverts the traffic to another local TCP port.

- The return traffic is also taken care : the source port (outbound) will also be updated with the original port.

- The process listening on the new port should listen on the same interface where the original port listens. 
