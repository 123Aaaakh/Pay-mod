import unittest
import sys
import os

# Add src to path for testing
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from paymod.core import PayloadManipulator

class TestPayloadCore(unittest.TestCase):
    def setUp(self):
        self.manipulator = PayloadManipulator()
        self.manipulator.data = bytearray(b"Hello World")
    
    def test_replace_string(self):
        count = self.manipulator.replace_string(b"World", b"Users")
        self.assertEqual(count, 1)
        self.assertEqual(self.manipulator.data, b"Hello Users")
        self.assertTrue(self.manipulator.modified)

    def test_patch_bytes(self):
        success = self.manipulator.patch_bytes(0, b"J")
        self.assertTrue(success)
        self.assertEqual(self.manipulator.data[0:1], b"J")
        self.assertEqual(self.manipulator.data, b"Jello World")

if __name__ == '__main__':
    unittest.main()
