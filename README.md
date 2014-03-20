openflow-test
=============

Code for openflow packet crafter and dissector in python scapy.
Supports only OF 1.3 for now.


Use cases:

1. Openflow conformance of various OF enabled devices.
2. We can spawn multiple instances of the script to test robustness of controller.
Add more.

To Do:

1. Support all types of OF messages - Hello, Echo and Features are done
2. Integrate the automata so that the script can act as a controller and keep a track of sessions with various devices connected to it
3. Documentation. :)

