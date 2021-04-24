import pandas as pd
import os
import id_pkg as intrusion_detect

debug = False
def show_aggie_pride():
    # https://pandas.pydata.org/docs/user_guide/index.html
    df = pd.DataFrame(['Aggie Pride', 'Worldwide', 'Aggies Do', 'Go Aggies', 'Aggies', 'GHOE!',
                       'Achievement', 'We Graduating!!', 'A-G-G-I-E', 'NCAT',
                       'Aggie Born, Aggie Bred, When I\'m gone I\'ll be Aggie Dead',
                       'Greatest Homecoming On Earth', 'Mens et Manus (Mind and Hand)',
                       'yay aggies','AGGIES CODE!', 'Aggie Land Forever', 'Greatest HBCU',
                       'Aggies All The Way', 'A-G-G-I-E'])

    print(df)


def pandas_demo():
    """Shows how to use some pandas features needed to implement sprint 4"""
    # The pandas help guide can be found here:
    # https://pandas.pydata.org/docs/user_guide/index.html

    # build a platform-safe path to the log file
    # PC paths are "c:\dir\file" where linux and mac use "/dir/file"
    # os.path.join() guarantees the correct path separator is used
    log_file = os.path.join('id_pkg', 'data')
    log_file = os.path.join(log_file, 'intrusion_logs.txt')

    # Create an intrusion detection object similar to
    # what was done during sprint 3
    log = intrusion_detect.IdParse(log_file)

    # Are there spoofing attacks in this log?
    if log.has_ip_spoofing():
        print('Spoofing attacks are present')



if __name__ == "__main__":
    # show_aggie_pride()
    pandas_demo()