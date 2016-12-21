import json
import sys
import random
from random import randint

from enums import *
from cybox_generator import *
from util import Util as u

#M_0 = 10



bundle = False
SDOs = []
SROs = []
sightings = []
markings = []
granular_markings = []

class Generator():
    """
        Generator class generates data sets with given parameters

        typical usage:

        sg = Generator(total_num = 1000, M_0_num = 5, indicator_num = 500)
        stix_data = sg.generate()

    """

    def __init__(self, total_num = 100, sighting_num = 0, marking_num = 0, granular_marking_num = 0, M_0_num = 2, indicator_num = 0, observed_data_num = 0, report_num = 0):
        """
            Initializes generator object with all the peramaters

            Args:
                total_num: total number of nodes to generate discluding indicator, observed_data, and report type nodes_to_generate
                sightings_num: how many sightings to generates
                marking_num: how many data markings to generates
                granular_marking_num: how many granular markings to generate (assignment will be random)
                M_0_num: used with the internal model of how many links to generate.  Basically there will me (total_num - M_0_num) * M_0_num relationships betweet teh total_num nodes
                indicator_num: how many indicators to generate, will randomly place them, and won't place them if it can't find anywhere to place them
                observed_data_num: how many observed data nodes to generate
                report_num: how many report nodes to generate
        """

        self.stix = []

        self.nodes_to_generate = int(total_num)
        self.sightings_num = int(sighting_num)
        self.markings_num = int(marking_num)
        self.observed_data_num = int(observed_data_num)
        self.report_num = int(report_num)
        self.indicator_num = int(indicator_num)
        self.M_0 = int(M_0_num)
        self.granular_markings_num = int(granular_marking_num)



    def generate(self):
        """
            Generates nodes using the parameters given upon initialization, and returns it as a dictionary
        """
        self.stix = generate_using_ba_model(self.nodes_to_generate, self.sightings_num, self.markings_num, self.granular_markings_num, self.M_0, self.indicator_num, self.observed_data_num, self.report_num, True)

        return self.stix


def make_sdo(SDOtype, version = "1", created = u.getcurrenttime(), modified = u.getcurrenttime(),
                    created_by_ref = "", revoked = False, labels = [], external_references = [], object_markings = [], granular_markings = []):
        """
            Makes a base SDO/STIX object (this also works with SROs) using essential properties defined in STIX documents
        """
        data = {}
        data['id'] = u.get_id(SDOtype)
        data['type'] = SDOtype
        data['created'] = created
        data['modified'] = modified
        data['version'] = int(version)
        data['created_by_ref'] = created_by_ref
        data['revoked'] = revoked
        data['labels'] = labels
        data['external_references'] = external_references
        data['object_markings'] = object_markings
        data['granular_markings'] = granular_markings

        return data

def make_namedesc_sdo(SDOtype, name, description = "none", labels = [], created_by_ref = ""):
    """
        Makes an SDO that has a name and a description.  This is the base function for all the main SDOs like malware



    """
    data = make_sdo(SDOtype, "1", labels = labels, created_by_ref = "")
    data['name'] = name
    data['description'] = description
    return data

def make_marking_definition(definition_type, definition, created_by_ref = "", created = u.getcurrenttime(), external_references = [], object_markings_ref = [], granular_markings = []):
    """
        Makes a marking definition (goes in the "markings definitions" array of bundle)

    """

    marking = {}
    marking['id'] = u.get_id("marking-definition")
    marking['type'] = "marking-definition"
    marking['created'] = created
    marking['created_by_ref'] = created_by_ref
    marking['external_references'] = external_references
    marking['object_markings_ref'] = object_markings_ref
    marking['granular_markings'] = granular_markings
    marking['definition_type'] = definition_type
    marking['definition'] = definition
    return marking

def make_statement_marking(statement, created_by_ref = ""):
    """
        Makes a statement marking definition
    """
    markings = {"statement": statement}
    marking = make_marking_definition("statement", markings, created_by_ref = created_by_ref)

    return marking

def make_tlp_marking(tlp, created_by_ref = ""):
    """
        Makes a tlp marking definition
    """
    markings = {"tlp": tlp}
    marking = make_marking_definition("tlp", marking-definition, created_by_ref = created_by_ref)

    return marking

def make_granular_marking(marking_defs, selectors):
    """
        Makes a granular marking reference from STIX.  This goes in the granular_markings list of an object

        example result:
        "granular_markings": [
            {
            "marking_ref": "SOME UUID THAT IS VALID BUT NOT REALLY",
            "selectors": ["description", "labels"]
            }
        ],
    """
    return {"marking_ref": marking_defs, "selectors": selectors}


def make_relationship(relationship_type, source, target, description = "", labels = [], created_by_ref = ""):
    """
        Makes a relationship between a source and a traget with a given relationship_type

    """
    data = make_sdo("relationship", "1", labels = labels, created_by_ref = created_by_ref)
    data['relationship_type'] = relationship_type
    data['description'] = description
    data['source_ref'] = source['id']
    data['target_ref'] = target['id']

    return data

def make_random_relationship(source, target, created_by_ref = ""):
    """
        Makes a relationship between two nodes with a random relationship type picked from the possible relationship types
    """
    return make_relationship(u.get_relationship_type(source, target), source, target, created_by_ref = created_by_ref)


#probably doesn't work properly right now
def make_sighting(sighting_of_ref, first_seen = "", first_seen_precision = "", count = 0, observed_data_refs = [], where_sighted_ref = [], summary = False, labels = [], created_by_ref = ""):
    """
        Makes a sighting
    """
    data = make_sdo("sighting", "1", labels, created_by_ref = created_by_ref)
    data['sighting_of_ref'] = sighting_of_ref
    data['created'] = first_seen
    data['modified'] = first_seen
    data['first_seen'] = first_seen
    data['first_seen_precision'] = 'full'
    data['count'] = count
    data['observed_data_refs'] = observed_data_refs
    data['where_sighted_ref'] = where_sighted_ref
    data['summary'] = summary

    return data

def make_random_sighting(SDOs, SDO = None, created_by_ref = ""):
    """
        Makes a sighting with random conections to an SDO or a random SDO from a list of SDOs
    """
    if SDO == None:
        r = randint(0, len(SDOs) - 1)
        SDO = SDOs[r]

    return make_sighting(SDO['id'], u.getcurrenttime(), u.getcurrenttime(), randint(0, 10), [], [], False, created_by_ref = created_by_ref)

def make_attack_pattern(name, description = "attack pattern", kill_chain_phases = [], labels = [], created_by_ref = ""):
    """
        Makes an attack pattern
    """
    data = make_namedesc_sdo("attack-pattern", name, description, labels, created_by_ref = created_by_ref)
    data['kill_chain_phases'] = kill_chain_phases

    return data


def make_campaign(name, description = "campaign", aliases = [], first_seen = "", first_seen_precision = "", objective = "", labels = [], created_by_ref = ""):
    """
        Makes a campaign
    """
    data = make_namedesc_sdo("campaign", name, description, labels, created_by_ref = created_by_ref)
    data['aliases'] = aliases
    data['first_seen'] = first_seen
    data['first_seen_precision'] = first_seen_precision
    data['objective'] = objective

    return data


def make_coa(name, description ="course of action", labels = [], created_by_ref = ""):
    """
        Makes a course of action
    """
    data = make_namedesc_sdo("course-of-action", name, description, labels, created_by_ref = created_by_ref)

    return data

def make_identity(name, description ="identity", identity_class = "", sectors = [], regions = [], nationalities = [], contact_information = "", labels = [], created_by_ref = ""):
    """
        Makes an identity
    """
    data = make_namedesc_sdo("identity", name, description, labels, created_by_ref = created_by_ref)
    data['identity_class'] = identity_class
    data['sectors'] = sectors
    data['nationalities'] = nationalities
    data['contact_information'] = contact_information

    return data

def make_indicator(name, description ="indicator", pattern_lang = "cybox", pattern_lang_version = '1.0', pattern = "", valid_from = u.getcurrenttime(),
                    valid_from_precision = "", valid_until = u.getcurrenttime(addition = 10000), valid_until_precision = "", kill_chain_phases = [], labels = [], created_by_ref = ""):
    """
        Makes an indicator.  Pattterns can be made with the cybox generator
    """
    data = make_namedesc_sdo("indicator", name, description, labels, created_by_ref = created_by_ref)
    data['pattern_lang'] = pattern_lang
    data['pattern_lang_version'] = pattern_lang_version
    data['pattern'] = pattern
    data['valid_from'] = valid_from
    data['valid_from_precision'] = valid_from_precision
    data['valid_until'] = valid_until
    data['valid_until_precision'] = valid_until_precision
    data['kill_chain_phases'] = kill_chain_phases

    return data

def make_intrusion_set(name, description ="intrusion set", aliases = [], first_seen = "", first_seen_precision = "", goals = [],
                        resource_level = "", primary_motivation = "", secondary_motivations = "", region = "", country = "", labels = [], created_by_ref = ""):
    """
        Makes an intrusion set
    """

    data = make_namedesc_sdo("intrusion-set", name, description, labels, created_by_ref = created_by_ref)
    data['aliases'] = aliases
    data['first_seen'] = first_seen
    data['first_seen_precision'] = first_seen_precision
    data['goals'] = goals
    data['resource_level'] = resource_level
    data['primary_motivation'] = primary_motivation
    data['secondary_motivations'] = secondary_motivations
    data['region'] = region
    data['country'] = country
    return data


def make_malware(name, description ="malware", kill_chain_phases = [], labels = [], created_by_ref = ""):
    """
        Makes a malware
    """
    data = make_namedesc_sdo("malware", name, description, labels, created_by_ref = created_by_ref)
    data['kill_chain_phases'] = kill_chain_phases

    return data


def make_observed_data(number_observed, first_observed = "", last_observed = "", cybox = "", labels = [], created_by_ref = ""):
    """
        Makes an observed data
    """
    data = make_namedesc_sdo("observed-data", "", "", labels, created_by_ref = created_by_ref)
    data['first_observed'] = first_observed
    data['last_observed'] = last_observed
    data['number_observed'] = number_observed
    data['cybox'] = generate_ip_list_cybox()

    return data


def make_report(name, description ="report", published = "", object_refs = [], labels = [], created_by_ref = ""):
    """
        Makes a report
    """
    data = make_namedesc_sdo("report", name, description, labels, created_by_ref = created_by_ref)
    data['published'] = published
    data['object_refs'] = object_refs

    return data

def make_threat_actor(name, description ="threat actor", aliases = [], roles = [], goals = [], sophistication = ", created_by_ref = """,
                        resource_level = "", primary_motivation = "", secondary_motivations = [], personal_motivations = [], labels = [], created_by_ref = ""):
    """
        Makes a threat actor
    """

    data = make_namedesc_sdo("threat-actor", name, description, labels)
    data['aliases'] = aliases
    data['roles'] = roles
    data['goals'] = goals
    data['sophistication'] = sophistication
    data['resource_level'] = resource_level
    data['primary_motivation'] = primary_motivation
    data['secondary_motivations'] = secondary_motivations
    data['personal_motivations'] = personal_motivations
    data['labels'] = labels
    if (labels == []) :
        data['labels'].append(random.choice(THREAT_ACTOR_LABEL_OV))
    return data

def make_tool(name, description ="tool", kill_chain_phases = [], tool_version = "", labels = [], created_by_ref = ""):
    """
        Makes a tool object
    """
    data = make_namedesc_sdo("tool", name, description, labels, created_by_ref = created_by_ref)
    data["kill_chain_phases"] = kill_chain_phases
    data["tool_version"] = tool_version

    return data

def make_vulnerability(name, description ="vulnerability", labels = [], created_by_ref = ""):
    """
        Makes a vulnerability object
    """
    data = make_namedesc_sdo("vulnerability", name, description, labels, created_by_ref = created_by_ref)

    return data

def make_kill_chain(kill_chain_name, phase_names):
    """
        Makes a kill chain with a given kill chain and a phase for every name in a
        list of given kill chain phase names
    """
    kill_chain_phases = []
    for name in phase_names:
        kill_chain_phases.append(make_kill_chain_phase(kill_chain_name, name))


    return kill_chain_phases


def make_kill_chain_phase(kill_chain_name, phase_name):
    """
        Makes a kill chain phase for a kill chain
    """
    return  {
        "kill_chain_name": kill_chain_name,
        "phase_name": phase_name
    }


def chose_rand_list(tlist, max_lenght = 10):
    """
        Unitility function to get a sample of random lenght [0, max_lenght] from
        a give list "tlist"
    """
    l = []
    rand_lenght = randint(0, max_lenght)
    for i in range(1, rand_lenght):
            l.append(random.choice(tlist))

    return l

def random_sdo(typenum = -1):
    """
        Makes a random SDO

        Args:
            typenum: specify the type with a number like so:

            1 = attack_pattern
            2 = campaign
            3 = coa
            4 = identity
            5 = indicator
            6 = intrusion_set
            7 = malware
            8 = observed_data
            9 = report
            10 = threat_actor
            11 = tool
            12 = vulnerability
    """

    if(typenum == -1 or typenum < 1 or typenum > 12):
        typenum = TYPES.index(random.choice(GENERATABLE_TYPES)) + 1

    text = random.choice(RANDOM_WORDS)

    name = u.make_random_name()
    motivation = random.choice(ATTACK_MOTIVATIONS_OV)
    motivations = chose_rand_list(ATTACK_MOTIVATIONS_OV, 4)
    resource_l = random.choice(ATTACK_RESOURCE_LEVEL_OV)
    indentity_c = random.choice(IDENTITY_CLASS_OV)
    indicator_l = random.choice(INDICATOR_LEVEL_OV)
    sectors = chose_rand_list(INDUSTRY_SECTOR_OV, 5)
    malware_l = random.choice(MALWARE_LABEL_OV)
    report_l = random.choice(REPORT_LABEL_OV)
    ta_l = random.choice(THREAT_ACTOR_ROLE_OV)
    ta_role = chose_rand_list(THREAT_ACTOR_ROLE_OV, 3)
    attack_so = random.choice(ATTACK_SOPHISTICATION_LEVEL_OV)
    tool_l = random.choice(TOOL_LABEL_OV)
    kill_chain = make_kill_chain(random.choice(KILL_CHAIN_NAMES), DEFAULT_KILL_PHASES)
    description = random.choice(RANDOM_ALIASES)
    aliases = chose_rand_list(RANDOM_ALIASES, 2)
    regions = ["new-brunswick", "ontario", "narnia"]
    nation = ["cn"]

    if(typenum == 1):
        return make_attack_pattern(text + " attack pattern", description, kill_chain)
    elif(typenum == 2):
        return make_campaign(text + " campaign", description, aliases, u.getcurrenttime(True))
    elif(typenum == 3):
        return make_coa(text + " coa", description)
    elif(typenum == 4):
        return make_identity(name, description, indentity_c, sectors, regions , nation , "555 555 5555")
    elif(typenum == 5):
        return make_indicator(text + " indicator", description, pattern =  generate_pattern_eq_ipv4(generate_dummy_ip()),  valid_from = u.getcurrenttime(True), valid_until = u.getcurrenttime(True), kill_chain_phases = kill_chain, labels = [indicator_l])
    elif(typenum == 6):
        return make_intrusion_set(text + " intrusion set", description, aliases, u.getcurrenttime(True), "full", ["do-damage"], resource_l, motivation, motivations, regions[0], nation[0])
    elif(typenum == 7):
        return make_malware(text + "ware", description, kill_chain, labels = [malware_l])
    elif(typenum == 8):
        return make_observed_data(first_observed = u.getcurrenttime(True), last_observed = u.getcurrenttime(True), number_observed = randint(0, 100))
    elif(typenum == 9):
        return make_report(text + " report", description, u.getcurrenttime(True), labels  = [report_l], object_refs = "")
    elif(typenum == 10):
        return make_threat_actor(random.choice(RANDOM_ALIASES), description, aliases, ta_role, ["do-damage"], attack_so, resource_l, motivation, motivations, motivations)
    elif(typenum == 11):
        return make_tool(name + "'s T00L'", description, kill_chain, "V" + str(randint(0, 10)) + "." + str(randint(0, 100)), labels = [tool_l])
    elif(typenum == 12):
        return make_vulnerability(text + " vulnerability", description)

def make_random_markings(num = 5):
    """
        Makes a random number of statement marking definitions
    """
    markings = []
    for i in range(0, num):
        markings.append(make_statement_marking("COPYRIGHT - NO ONE, THIS IS RANDOM DATA"))

    return markings

def randomly_assign_object_markings(sdos, markings):
    """
        Randomly assigns object markings to sdos

        Args:
            sdos: the nodes that can receive markings
            markings: marking definitions to assign
    """
    for marking in markings:
        rand = randint(0, len(sdos) - 1)
        sdos[rand]['object_markings']  = sdos[rand]['object_markings'] + [marking['id']]

    return sdos


def randomly_assign_granular_markings(sdos, markings):
    """
        Randomly assigns granular markings to sdos

        Args:
            sdos: the nodes that can receive markings
            markings: marking definitions to assign
    """

    for marking in markings:
        rand = randint(0, len(sdos) - 1)
        sdo = sdos[rand]

        randselectors = randint(1, len(sdo.keys()))
        selectors=[]

        for i in range(0, randselectors-1):
            selectors.append(random.choice(sdo.keys()))

        mark = make_granular_marking([marking['id']], selectors)
        sdos[rand]['granular_markings']  = sdos[rand]['granular_markings'] + [mark]

    return sdos

# requires nodes_to_generate to be larger than M_0
def generate_using_ba_model(nodes_to_generate, sighting_num = 0, markings_num = 0, granular_markings_num = 0, M_0 = 2, indicator_num = 0, observed_data_num = 0, report_num = 0, show_progress = False):
    """
        The model used to generate random nodes.

        Args:
            nodes_to_generate: total number of nodes to generate discluding indicator, observed_data, and report type nodes_to_generate
            sightings_num: how many sightings to generates
            marking_num: how many data markings to generates
            granular_marking_num: how many granular markings to generate (assignment will be random)
            M_0_num: used with the internal model of how many links to generate.  Basically there will me (total_num - M_0_num) * M_0_num relationships betweet teh total_num nodes
            indicator_num: how many indicators to generate, will randomly place them, and won't place them if it can't find anywhere to place them
            observed_data_num: how many observed data nodes to generate
            report_num: how many report nodes to generate
            show_progress: wether or not to show the progress in the console

        Returns:
            A list of dicts containing all the python objects (will need to go
            though bundler before being valid)

    """
    SDOs = []
    SROs = []
    sightings = []
    markings = []
    granular_markings = []

    if(nodes_to_generate < M_0):
        print "nodes_to_generate < M_0. Please enter a larger numer"
        return;

    prog = 0

    if show_progress:
        print "generating", nodes_to_generate, "nodes"

    for i in range(nodes_to_generate):
        print nodes_to_generate/int(nodes_to_generate * 0.5)
        if prog % int(nodes_to_generate/int(nodes_to_generate * 0.5)) == 0 and show_progress:
            print (prog * 100)/nodes_to_generate, "%"
        SDOs.append(random_sdo())

        prog +=1

    prog = 0
    print "Generating", len(SDOs) * M_0 - M_0*M_0, "relationships"
    #make relationships using the Barabasi-Albert model for generating social networks
    for i in range(M_0, len(SDOs)):
        if prog % int(len(SDOs)/int(len(SDOs) * 0.5)) == 0 and show_progress:
            print (prog * 100)/len(SDOs), "%"

        not_selected = list(range(0, i))
        #chance generate reports if an incident
        if(SDOs[i]['type'] is 'incident' and randint(0,2) is 1) :
            SDOs.append(random_sdo(9))
            SDOs[-1][object_refs].append(SDOs[i])

        for j in range(0, M_0):
            src_type = SDOs[i]['type']
            choice = random.choice(not_selected)
            not_selected.remove(choice)
            target_type = SDOs[choice]['type']
            relationship_type = random.choice(RELATIONSHIPS[src_type].get(target_type, {'related-to': 'forward' }).keys())

            if (relationship_type == 'related-to' or RELATIONSHIPS[src_type][target_type][relationship_type]  == 'forward') :
                SROs.append(make_relationship(relationship_type, SDOs[i], SDOs[choice]))
            else :
                SROs.append(make_relationship(relationship_type, SDOs[choice], SDOs[i]))
            #SROs.append(make_random_relationship(SDOs[i], SDOs[rand]))

        prog +=1


    prog = 0
    print "Generating", indicator_num, "indicators"
    #generate indicators
    for i in range(indicator_num):
        if prog % int(indicator_num/int(indicator_num * 0.5)) == 0 and show_progress:
            print (prog * 100)/indicator_num, "%"
        counter = 100
        while True:
            target = random.choice(SDOs)

            if target['type'] in RELATIONSHIPS['indicator']:
                SDOs.append(random_sdo(5))
                SROs.append(make_relationship('indicates', SDOs[-1], target))
                break;

            if counter is 0:
                break

            counter -= 1

        prog += 1


    prog = 0
    print "Generating", observed_data_num, "observed data"
    #generate observable data
    for i in range(observed_data_num):
        if prog % int(observed_data_num/int(observed_data_num * 0.5)) == 0 and show_progress:
            print (prog * 100)/observed_data_num, "%"

        SDOs.append(random_sdo(8))

        prog += 1
    # TODO
    # for i in range(observed_data_num):
    #     SDOs.append(random_sdo(8, nodes_text))
    #     if(target['type'] in RELATIONSHIPS['indicator']):
    #         SROs.append(make_relationship('related-to', SDOs[-1], random.choice(SDOs)))


    prog = 0
    print "Generating", sighting_num, "sightings"
    #make sightings
    for i in range(0, sighting_num - 1):
        if prog % int(sighting_num/int(sighting_num * 0.5)) == 0 and show_progress:
            print (prog * 100)/sighting_num, "%"

        sightings.append(make_random_sighting(SDOs))

        prog += 1

    #make markings

    print "Generating markings"
    markings = make_random_markings(markings_num)
    granular_markings = make_random_markings(granular_markings_num)

    randomly_assign_object_markings(SDOs, markings)
    randomly_assign_granular_markings(SDOs, granular_markings)

    stix = u.clean_stix_data(SDOs + SROs + sightings + markings + granular_markings)

    return stix

def main():
    gen = Generator(total_num = 10, M_0_num = 2, indicator_num = 4)

    u.make_output(gen.generate(), "STIX.json")

if __name__ == "__main__":
    main()
