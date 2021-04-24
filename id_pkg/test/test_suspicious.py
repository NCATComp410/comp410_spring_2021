import unittest
import os
import git
import id_pkg as intrusion_detect

class TestSuspicious(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'intrusion_logs.txt')

    log = intrusion_detect.IdParse(syslog_file)

    def test_get_low_severity(self):
        # Find low severity messages
        low_severity = self.log.get_low_severity()


        print('These are the unique low severity messages')
        print(low_severity['ID'].unique())

        self.assertListEqual([305011, 713160], list(low_severity['ID'].unique()))

    def test_get_high_severity(self):

        attacks = self.log.get_high_severity()

        print(attacks['ID'].unique())

        self.assertListEqual([733100, 109017, 713162, 313004, 106016, 733101, 419002, 106001], list(attacks['ID'].unique()))

    def test_get_suspicous(self):

        suspicous = self.log.get_suspicious()
        print(suspicous['Source'])

        suspicous.to_excel('suspicious.xlsx')




if __name__ == '__main__':
    unittest.main()
