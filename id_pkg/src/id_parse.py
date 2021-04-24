from id_pkg import LogParse
import pandas as pd
import re


class IdParse(LogParse):
    df = pd.DataFrame()

    def __init__(self, syslog_file):
        self.syslog_to_dataframe(syslog_file)

    def has_ip_spoofing(self):
        # https://pandas.pydata.org/docs/reference/api/pandas.Series.any.html
        # Returns true if the ip spoofing id appears in the dataframe
        return (self.df['ID'] == 106016).any()

    def has_bad_packets(self):
        # https://pandas.pydata.org/docs/reference/api/pandas.Series.any.html
        return (self.df['ID'] == 324301).any()

    def has_icmp(self):
        # https://pandas.pydata.org/docs/reference/api/pandas.Series.any.html
        # Returns true if the ip spoofing id appears in the dataframe
        return (self.df['ID'] == 313008).any()

    def has_scanning(self):
        # Returns true if the scanning id appears in the dataframe
        return (self.df['ID'] == 733101).any()

    def has_ACLDrop(self):
        return (self.df['ID'] == 710003).any()

    def get_low_severity(self):
        return self.df[self.df['Severity'] >= 6]

    def get_high_severity(self):
        return self.df[self.df['Severity'] <= 5]


    def handle_asa_message(self, rec):
        """Implement ASA specific messages"""
        # %ASA-3-324301: Radius Accounting Request has a bad header length hdr_len, packet length pkt_len
        if rec['ID'] == 324301:
            m = re.search(r'Radius Accounting Request has a bad header length (\d+), packet length (\w+)', rec['Text'])
            if m:
                rec['Header Length'] = m.group(1)
                rec['Packet Length'] = m.group(2)

        # %ASA-2-106016: Deny IP spoof from (10.1.1.1) to 10.11.11.19 on interface TestInterface
        if rec['ID'] == 106016:
            m = re.search(r'Deny IP spoof from \((\d+\.\d+\.\d+\.\d+)\) to (\d+\.\d+\.\d+\.\d+) on interface (\w+)', rec['Text'])
            if m:
                rec['Source'] = m.group(1)
                rec['Destination'] = m.group(2)
                rec['Interface'] = m.group(3)

        # %ASA-3-710003: {TCP|UDP} access denied by ACL from source_IP/source_port to interface_name:dest_IP/service
        elif rec['ID'] == 710003:
            m = re.search(r'UDP access denied by ACL from (\d+\.\d+\.\d+\.\d+) port (\d+) to interface_name:(\w+)', rec['Text'])
            if m:
                rec['Source'] = m.group(1)
                rec['Port'] = m.group(2)
                rec['Interface'] = m.group(3)

        elif rec['ID'] == 313008:
            # %ASA-3-313008: Denied ICMPv6 type=number , code=code from IP_address on interface interface_name
            message = re.search(r'Denied ICMPv6 type=(\d+), code=(\d+) from (\d+\.\d+\.\d+\.\d+) on interface (\w+)', rec['Text'])
            if message:
                rec['Number'] = message.group(1)
                rec['Code'] = message.group(2)
                rec['Source'] = message.group(3)
                rec['Interface'] = message.group(4)

        # %ASA-4-733101: Host 175.0.0.1 is attacking. Current burst rate is 200 per second, max configured rate is 0;
        # Current average rate is 0 per second, max configured rate is 0; Cumulative total count is 2024
        elif rec['ID'] == 733101:
            m = re.search(r'(\d+\.\d+\.\d+\.\d+) is attacking', rec['Text'])
            if m:
                rec['Source'] = m.group(1)

        # %ASA-2-106001: Inbound TCP connection denied from 10.132.0.177/2257 to 172.16.10.177/80 flags SYN on interface inside TestInterface
        elif rec['ID'] == 106001:
            rec['Attack'] = True
            m = re.search(r'Inbound TCP connection denied from (\d+\.\d+\.\d+\.\d+)/(\d+) to (\d+\.\d+\.\d+\.\d+)/(\d+) flags SYN on interface inside (\w+)', rec['Text'])
                if m:
                    rec['Source'] = m.group(1)
                    rec['Source Port'] = m.group(2)
                    rec['Destination'] = m.group(3)
                    rec['Destination Port'] = m.group(4)
                    rec['Interface'] = m.group(5)

        return rec

    def handle_syslog_message(self, line):
        """Parses basic information out of a syslog file"""
        m = re.search(r'^(\w+ \w+ \w+ \d+:\d+:\d+) (\w+) : %(\w+)-(\d)-(\d+): (.+)', line)
        # If the re matched
        if m:
            return self.handle_asa_message({'Date': m.group(1),
                                            'Host': m.group(2),
                                            'Type': m.group(3),
                                            'Severity': int(m.group(4)),
                                            'ID': int(m.group(5)),
                                            'Text': m.group(6)})
        else:
            return {}

    def syslog_to_dataframe(self, syslog_file):
        """Returns a dataframe from a sample syslog file"""
        # Improve pandas performance by creating a list first
        rec_list = []
        # Read the syslog file and parse it into our dataframe
        with open(syslog_file, encoding='utf-8') as f:
            for line in f:
                # Create a record to hold this line in the syslog file
                rec_list.append(self.handle_syslog_message(line))
        # Create the dataframe from the list
        self.df = pd.DataFrame(rec_list)
