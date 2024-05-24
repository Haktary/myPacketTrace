import unittest
from unittest.mock import patch
from PacketManipulator import *

class TestPacketManipulator(unittest.TestCase):

    def test_edit_packet(self):
        test_packet = IP(src='192.168.1.1', dst='8.8.8.8')/TCP(sport=1234, dport=80)

        edited_packet = edit_packet(test_packet, new_src_ip='10.0.0.1', new_dst_ip='192.168.1.2')

        # Assert the edited packet's properties
        self.assertEqual(edited_packet[IP].src, '10.0.0.1')
        self.assertEqual(edited_packet[IP].dst, '192.168.1.2')

    def test_filter_func(self):
        test_packet1 = IP(dst='74.125.250.244')/UDP()
        test_packet2 = IP(dst='8.8.8.8')/TCP()

        self.assertTrue(filter_func(test_packet1, dst_ip='74.125.250.244', protocol=UDP))
        self.assertFalse(filter_func(test_packet2, dst_ip='74.125.250.244', protocol=UDP))

    '''
    @patch('PacketManipulator.conf')
    def test_choose_interface(self, mock_conf):
        return
    '''

    @patch('PacketManipulator.sniff')
    def test_capture_packets(self, mock_sniff):
        mock_packets = [IP() for _ in range(10)]
        mock_sniff.return_value = mock_packets

        captured_packets = capture_packets('eth0', 10)
        self.assertEqual(len(captured_packets), 10)

if __name__ == '__main__':
    unittest.main()
