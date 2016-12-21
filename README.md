# STIX Generator

##Requirements
Supports Python 2.6/2.7

Copy the stix_generator into the directories that will use it (TODO make this an actual package for pip install)

##Stix Generator
stix_generator.py contains the "Generator" class, which is used to make random data.  The parameters for the generator are in the constructor 
 
```python

from stix_generator.stix_generator import Generator

#make the generator
sg = Generator(total_num, sightings_num, marking_num, granular_marking_num, M_0_num, indicator_num, observed_data_num, report_num)

#make the data.  stix is a list of dicts
stix = sg.generate()

#write stix to the specified path
u.make_output(stix, /STIX_data.json)
```

The file also contains functions to make different types of STIX objects, which can be put an in a list and be used the same way as the "stix".

```
stix = [make_threat_actor(), make_indicator(), make_malware()]

u.make_output(stix, /STIX_data.json)
```

##Cybox Generator
*This code isn't complete*

The file also contains methods to make different types of Cybox observables, and to make patterns.  Not all observables are included yet, and the pattern generator only makes ip addresses.
 
 
this will make a pattern that will detect 10 random ips:

```
finish_pattern(generate_pattern_eq_ipv4_list(generate_random_ip_list(10)))
```

##make_nodes.py
This script uses the STIX_generator to make random data.  You can put the parameters in the script and run it like such

```
python make_nodes.py path/of/the/json/destination
```
 
