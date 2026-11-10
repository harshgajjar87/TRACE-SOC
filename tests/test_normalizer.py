import sys
import os

# Ensure the project root is on the path when running this file directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from normalizer.event_schema import convert_pid


def test_decimal_pid():

    assert convert_pid("1234") == 1234


def test_hexadecimal_pid():

    assert convert_pid("0x1a2c") == 6700


def test_missing_pid():

    assert convert_pid(None) is None


def test_invalid_pid():

    assert convert_pid("unknown") is None


if __name__ == "__main__":

    test_decimal_pid()
    test_hexadecimal_pid()
    test_missing_pid()
    test_invalid_pid()

    print("All PID tests passed!")