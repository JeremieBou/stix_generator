import sys
import os


from stix_generator.util import Util as u
from stix_generator.stix_generator import Generator


def main():
    """
        example script for STIX Generator

        makes random stix data using the generator with set peramaters in the script
    """

    path = os.path.realpath('static/data') + "/view.json"
    if(len(sys.argv) is 2):
        total_num = 100
        sightings_num = 0
        marking_num = 0
        granular_marking_num = 0
        M_0_num = 2
        indicator_num = 50
        observed_data_num = 0
        report_num = 0

        print "M_0 =  " + str(M_0_num)
        print "Generating " + str(total_num) + " nodes"
        print "Generating " + str(sightings_num) + " sightingss"
        print "Generating " + str(marking_num) + " markings"
        print "Generating " + str(granular_marking_num) + " granular_markings"
        print "Generating " + str(indicator_num) + " indicators"
        print "Generating " + str(observed_data_num) + " observed_datas"
        print "Generating " + str(report_num) + " reports"

        sg = Generator(total_num, sightings_num, marking_num, granular_marking_num, M_0_num, indicator_num, observed_data_num, report_num)

        stix = sg.generate()

        print "Done generating, making output"

        u.make_output(stix, str(sys.argv[1]))

        print "Complete"
    # No Arguments given
    else:
        print "Please specify the ouput directory."

if __name__ == "__main__":
    main()
