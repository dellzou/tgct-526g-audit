import unittest

from tgct526g.wan import WanParseError, decode_password, parse_wan_connstr

SAMPLE = r'''
<html><head><script>
var WanConnStr =  "1_TR069_VOIP_R_VID_46|2|5|0|0|0|46|7|1492|13.243.228.161|255.255.255.0|13.243.228.1|192.168.200.1|0.0.0.0|veip0.1|1|0|0|DHCPv6|0|(null)|(null),PrefixDelegation|(null)|192.168.200.1|0.0.0.0|0|0||2|0|126|1|1|1|(null)|0}3_INTERNET_R_VID_41|0|2|29|1|1|41|0|1492|07551234567890@163.gd|ZGVtb3Bhc3M=||||ppp1.3|1|0|1|AutoConfigured|1|(null)|(null),PrefixDelegation|(null)|202.96.128.166|202.96.134.133|0|0||0|0|0|0|0|2|0|133|1|4|1|(null)|1";
</script></head></html>
'''


class TestWanParser(unittest.TestCase):
    def test_decode_password(self):
        self.assertEqual(decode_password("ZGVtb3Bhc3M="), "demopass")

    def test_parse_internet_record(self):
        info = parse_wan_connstr(SAMPLE)
        self.assertEqual(info.account, "07551234567890@163.gd")
        self.assertEqual(info.password, "demopass")
        self.assertEqual(info.vlan, "41")
        self.assertEqual(info.mtu, "1492")
        self.assertEqual(info.ifname, "ppp1.3")
        self.assertIn("INTERNET", info.service)

    def test_missing_variable(self):
        with self.assertRaises(WanParseError):
            parse_wan_connstr("<html>login</html>")

    def test_missing_internet_record(self):
        with self.assertRaises(WanParseError):
            parse_wan_connstr('var WanConnStr = "1_TR069|2|3";')


if __name__ == "__main__":
    unittest.main()
