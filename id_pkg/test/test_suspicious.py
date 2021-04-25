import unittest
import git
import os
import id_pkg as intrusion_detect
import pandas as pd


class TestSuspicious(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'intrusion_logs.txt')

    log = intrusion_detect.IdParse(syslog_file)

    def test_get_low_severity(self):
        # Find low severity messages
        low_sev = self.log.get_low_severity()
        print("List of unique low severity messages")
        print(low_sev['ID'].unique())
        self.assertListEqual([305011, 713160], low_sev['ID'].unique().tolist())

    def test_get_high_severity(self):
        attacks = self.log.get_high_severity()
        print("List of unique high severity messages")
        print(attacks['ID'].unique())

        self.assertListEqual([733100, 109017, 713162, 313004, 106016, 733101, 419002, 106001], attacks['ID'].unique().tolist())

    def test_get_suspicious(self):
        sus = self.log.get_suspicious()
        print("List of suspicious sources")
        print(sus['Source'])

        sus.to_excel('suspicious.xlsx')
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
