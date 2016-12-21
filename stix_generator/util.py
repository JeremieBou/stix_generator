import time
import datetime
import uuid
import json
import random
from random import randint
import os

from enums import *

class Util:
    """
        Class that contains several utility functions
    """

    @staticmethod
    def make_random_name():
        """
            makes a random name out of two arrays in enums.py
        """
        return random.choice(RANDOM_GIVENNAMES) + " " + random.choice(RANDOM_SURNAMES)


    #TODO update this to work with new bundles
    @staticmethod
    def bundle_stix(STIX):
        """
            puts a list of stix object into a bundle.  **** this uses bundle system
            where there's a key for each type and lists of those types
        """
        STIX_bundle = {}

        STIX_bundle["type"] ="bundle"
        STIX_bundle["id"] = Util.get_id(STIX_bundle['type'])
        STIX_bundle["spec_version"] ="2.0"

        for obj in STIX:
            key = Util.make_into_bundle_name(obj['type'])


            if STIX_bundle.get(key, None) is None:
                STIX_bundle[key] = [obj]
            else:
                STIX_bundle[key].append(obj)
        return STIX_bundle


    @staticmethod
    def make_output(STIX, path = "/STIX_data.json"):
        """
            Given a list of stix  objects this makes an output at the specified path

            Args:
                STIX: list of stix objects
                path: location where to save the output
        """
        try:
            with open(path, 'w') as fp:
                json.dump(Util.bundle_stix(STIX), fp)
        except:
            print "Unable to access directory '", path, "'\n", "Using default directory"

            with open("STIX_data.json", 'w') as fp:
                json.dump(Util.bundle_stix(STIX), fp)


    @staticmethod
    def getcurrenttime(changetime = False, addition = 0):
        """
            returns valid stix time stamp with the current time
        """

        if changetime:
            add = randint(-100000, 100000)

        return datetime.datetime.fromtimestamp(time.time() + addition).strftime('%Y-%m-%dT%H:%M:%S.%mZ')

    @staticmethod
    def make_into_bundle_name(word):
        """
            makes the bundle name for the key for that object type
            (e.g. threat-actor become threat_actors)
        """
        return BUNDLE_NAMES.get(word, word + 's')

    @staticmethod
    def get_relationship_type(source, target):
        """
            gets a valid relationship type from two given nodes
        """
        return RELATIONSHIPS[source['type']].get(target['type'], 'connected-to').keys()[0]

    @staticmethod
    def get_id(name):
        """
            generates uuid for stix object
        """
        return name + "--" + str(uuid.uuid4())

    @staticmethod
    def clean_stix_data(STIX):
        """
            Cleans stix data by removing every property left blank
        """
        for obj in STIX:
            obj = Util.clean_dict(obj)
        return STIX

    @staticmethod
    def clean_dict(sdict):
        keys_to_remove = []
        for key, value in sdict.iteritems():
            if type(value) is list:
                if len(value) < 1:
                    keys_to_remove.append(key)
            elif type(value) == dict:
                if not value:
                    keys_to_remove.append(key)
            elif type(value) == str:
                if len(value) < 1:
                    keys_to_remove.append(key)
            elif type(value) == int:
                if value < 0:
                    keys_to_remove.append(key)

            elif value == None:
                keys_to_remove.append(key)
        if('cybox' in keys_to_remove) :
            keys_to_remove.remove('cybox')
        for key in keys_to_remove:
            del sdict[key]

        return sdict
