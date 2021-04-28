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

    # %ASA-3-713163: Remote user (session Id - id) has been terminated by the Firewall Server
    def has_firewall(self):
        return (self.df['ID'] == 713163).any()

    # %ASA-2-106017: Deny IP due to Land Attack from IP_address to IP_address
    def has_denial_of_service(self):
        return (self.df['ID'] == 106017).any()

    def get_low_severity(self):
        return self.df[self.df['Severity'] >= 6]

    def get_high_severity(self):
        return self.df[self.df['Severity'] < 5]


    def handle_asa_message(self, rec):
        """Implement ASA specific messages"""
        # %ASA-2-106016: Deny IP spoof from (10.1.1.1) to 10.11.11.19 on interface TestInterface
        if rec['ID'] == 106016:
            m = re.search(r'from \((\d+\.\d+\.\d+\.\d+)\) to (\d+\.\d+\.\d+\.\d+) on interface (\w+)', rec['Text'])
            if m:
                rec['Source'] = m.group(1)
                rec['Destination'] = m.group(2)
                rec['Interface'] = m.group(3)
        # %ASA-3-713163: Remote user (session Id - id) has been terminated by the Firewall Server
        if rec['ID'] == 713163:
            m = re.search(r'Remote user \((\w+) - (\w+)\)', rec['Text'])
            if m:
                rec['Session'] = m.group(1)
                rec['Identifier'] = m.group(2)
        # %ASA-2-106017: Deny IP due to Land Attack from IP_address to IP_address
        if rec['ID'] == 106017:
            m = re.search(r'from (\d+\.\d+\.\d+\.\d+) to (\d+\.\d+\.\d+\.\d+)', rec['Text'])
            if m:
                rec['Source'] = m.group(1)
                rec['Destination'] = m.group(2)
          # %ASA-7-713160: Remote user (session Id - id) has been granted access by the Firewall Server
        if rec['ID'] == 713160:
            m = re.search(r' user \((\w+) - (\w+)\)', rec['Text'])
            if m:
                rec['Session'] = m.group(1)
                rec['Identifier'] = m.group(2)
         # %ASA-3-713162: Remote user (db248b6cbdc547bbc6c6fdfb6916eeb - 1) has been rejected by the Firewall Server
        if rec['ID'] == 713162:

            m = re.search(r'Remote user \((\w+) - (\w+)\) has been rejected by the Firewall Server',
                              rec['Text'])
            if m:
                rec['Source'] = m.group(1)
                rec['id'] = m.group(2)

        if rec['ID'] == 313008:
            # %ASA-3-313008: Denied ICMPv6 type=number , code=code from IP_address on interface interface_name
            message = re.search(
                r'Denied ICMPv6 type=(\d+), code=(\d+) from (\d+\.\d+\.\d+\.\d+) on interface (\w+)', rec['Text'])
            if message:
                rec['Number'] = message.group(1)
                rec['Code'] = message.group(2)
                rec['Source'] = message.group(3)
                rec['Interface'] = message.group(4)

        if rec['ID'] == 733100:
            m = re.search(r'rate-(\d+) exceeded. Current burst rate is (\d+) per second, max configured rate is ('
                          r'\d+); Current average rate is (\d+) per second, max configured rate is (\d+); Cumulative '
                          r'total count is (\d+)', rec['Text'])
            if m:
                rec['DropRate'] = m.group(1)
                rec['BurstRate'] = m.group(2)
                rec['MaxConfigRate1'] = m.group(3)
                rec['CurrentAverageRate'] = m.group(4)
                rec['MaxConfigRate2'] = m.group(5)
                rec['TotalCount'] = m.group(6)

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
