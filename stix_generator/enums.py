 # -*- coding: utf-8 -*-
#STIX open vocabulary and values

#simulate enums
TYPES = [
    "attack-pattern",
    "campaign",
    "course-of-action",
    "identity",
    "indicator",
    "intrusion-set",
    "malware",
    "observed-data",
    "report",
    "threat-actor",
    "tool",
    "vulnerability",
]

GENERATABLE_TYPES = [
    "attack-pattern",
    "campaign",
    "course-of-action",
    "identity",
#    "indicator",
    "intrusion-set",
    "malware",
#    "observed-data",
#    "report",
    "threat-actor",
    "tool",
    "vulnerability",
]

ATTACK_MOTIVATIONS_OV  = [
    'accidental',
    'coercion',
    'dominance',
    'ideology',
    'notoriety',
    'organizational-gain',
    'personal-gain',
    'personal-satisfaction',
    'revenge',
    'unpredictable'
 ]
 
ATTACK_RESOURCE_LEVEL_OV = [
    'individual',
    'club',
    'contest',
    'team',
    'organization',
    'government'
]

IDENTITY_CLASS_OV = [
    'individual',
    'group',
    'organization',
    'class',
    'unknown'
]

INDICATOR_LEVEL_OV = [
    'anomalous-activity',
    'anonymization',
    'benign',
    'compromised',
    'malicious-activity',
    'attribution'
]

INDUSTRY_SECTOR_OV = [
    "agriculture",
    "aerospace",
    "automotive",
    "communications",
    "construction",
    "defence",
    "education",
    "energy",
    "entertainment",
    "financial-services",
    "government-national",
    "government-regional",
    "government-local",
    "government-public-services",
    "healthcare",
    "hospitality-leisure",
    "infrastructure",
    "insurance",
    "manufacturing",
    "mining",
    "non-profit",
    "pharmaceuticals",
    "retail",
    "technology",
    "telecommunications",
    "transportation",
    "utilities"
]

MALWARE_LABEL_OV = [
    "adware",
    "backdoor",
    "bot",
    "ddos",
    "dropper",
    "exploit-kit",
    "keylogger",
    "ransomware",
    "remote-access-trojan",
    "resource-exploitation",
    "rogue-antivirus",
    "rootkit",
    "screen-capture",
    "spyware",
    "trojan",
    "virus",
    "worm"
]
PATTERN_LANG_OV = [
    'cybox',
    'openioc',
    'snort',
    'yara'
]

REPORT_LABEL_OV = [
    'threat-report',
    'attack-pattern',
    'campaign',
    'indicator',
    'malware',
    'observed-data',
    'threat-actor',
    'tool',
    'victim-target',
    'vulnerability'
]

THREAT_ACTOR_ROLE_OV = [
    'activist',
    'competitor',
    'crime-syndicate',
    'criminal',
    'hacker',
    'insider-accidental',
    'insider-disgruntled',
    'nation-state',
    'sensationalist',
    'spy',
    'terrorist'
]

THREAT_ACTOR_ROLE_OV=[
    'agent',
    'director',
    'independent',
    'infrastructure-architect',
    'infrastructure-operator',
    'malware-author',
    'sponsor'
]


ATTACK_SOPHISTICATION_LEVEL_OV = [
    'none',
    'minimal',
    'intermediate',
    'advanced',
    'expert',
    'innovator',
    'strategic'
]

TOOL_LABEL_OV = [
    'denial-of-service',
    'exploitation',
    'information-gathering',
    'network-capture',
    'credential-exploitation',
    'remote-access',
    'vulnerability-scanning'
]

BUNDLE_NAMES = {
    "attack-pattern": "attack_patterns",
    "campaign": "campaigns",
    "course-of-action": "courses_of_action",
    "identity": "identities",
    "indicator": "indicators",
    "intrusion-set": "intrusion_sets",
    "malware": "malware",
    "observed-data": "observed_data",
    "report": "reports",
    "threat-actor": "threat_actors",
    "tool": "tools",
    "vulnerability": "vulnerabilities",
    "marking-definition": "marking_definitions",
    "sighting": "sightings",
    "relationship": "relationships"
}

THREAT_ACTOR_LABEL_OV = [
    "activist",
    "competitor",
    "crime-syndicate",
    "criminal",
    "hacker",
    "insider-accidental",
    "insider-disgruntled",
    "nation-state",
    "sensationalist",
    "spy",
    "terrorist"
]

RELATIONSHIPS = {
    'attack-pattern': {
        'campaign': {
            'uses': 'reverse'
        },
        'course-of-action': {
            'mitigates': 'reverse'
        },
        'identity': {
            'targets': 'forward'
        },
        'indicator': {
            'indicates': 'reverse'
        },
        'intrusion-set': {
            'uses': 'reverse'
        },
        'malware' : {
            'uses': 'forward'
        },
        'threat-actor' :{
            'uses': 'reverse'
        },
        'tool' : {
            'uses': 'forward'
        },
        'vulnerability' : {
            'targets' : 'forward'
        }
    },
    'campaign': {
        'intrusion-set':{
            'attributed-to': 'forward'
        },
        'threat-actor' :{
            'attributed-to': 'forward'
        },
        'identity': {
            'targets': 'forward'
        },
        'indicator': {
            'indicates': 'reverse'
        },
        'vulnerability': {
            'targets': 'forward'
        },
        'attack-pattern': {
            'uses': 'forward'
        },
        'malware': {
            'uses': 'forward'
        },
        'tool': {
            'uses': 'forward'
        }
    },
    'course-of-action': {
        'attack-pattern': {
            'mitigates': 'forward'
        },
        'malware': {
            'mitigates': 'forward'
        },
        'tool': {
            'mitigates': 'forward'
        },
        'vulnerability': {
            'mitigates': 'forward'
        }
    },
    'identity': {
        "attack-pattern" : {
            "targets" : "reverse"
        },
        "campaign" : {
            "targets" : "reverse"
        },
        "intrusion-set" : {
            "targets" : "reverse"
        },
        "malware" : {
            "targets" : "reverse"
        },
        "threat-actor" : {
            "targets" : "reverse"
        },
        "tool" : {
            "targets" : "reverse"
        }
    },
    'indicator': {
        'attack-pattern': {
            'indicates': 'forward'
        },
        'campaign': {
            'indicates': 'forward'
        },
        'intrusion-set': {
            'indicates': 'forward'
        },
        'malware': {
            'indicates': 'forward'
        },
        'threat-actor': {
            'indicates': 'forward'
        },
        'tool': {
            'indicates': 'forward'
        }
    },
    'intrusion-set': {
        'campaign': {
            'attributed-to': 'reverse'
        },
        'threat-actor': {
            'attributed-to': 'forward'
        },
        'identity': {
            'targets': 'forward'
        },
        'indicator': {
            'indicates': 'reverse'
        },
        'vulnerability': {
            'targets': 'forward'
        },
        'attack-pattern': {
            'uses': 'forward'
        },
        'malware': {
            'uses': 'forward'
        },
        'tool': {
            'uses': 'forward'
        }
    },
    'malware': {
        "attack-pattern" : {
            "uses": "reverse"
        },
        "campaign" : {
            "uses": "reverse"
        },
        'course-of-action': {
            'mitigates': 'reverse'
        },
        "intrusion-set" : {
            "uses": "reverse"
        },
        "threat-actor" : {
            "uses": "reverse"
        },
        'identity': {
            'targets': 'forward'
        },
        'indicator': {
            'indicates': 'reverse'
        },
        'vulnerability': {
            'targets': 'forward'
        },
        'tool': {
            'uses': 'forward'
        },
        'malware': {
            'variant-of': 'forward',
        }
    },
    'threat-actor': {
        'attack-pattern': {
            'uses': 'forward'
        },
        'campaign': {
            'attributed-to': 'reverse'
        },
        'identity' : {
            'attributed-to': 'forward',
            'targets': 'forward'
        },
        'indicator': {
            'indicates': 'reverse'
        },
        'intrusion-set' : {
            'attributed-to': 'reverse'
        },
        'vulnerability': {
            'targets': 'forward'
        },
        'malware': {
            'uses': 'forward'
        },
        'tool': {
            'uses': 'forward'
        }
    },
    'tool': {
        "attack-pattern": {
            "uses": "reverse"
        },
        "campaign": {
            "uses": "reverse"
        },
        'course-of-action': {
            'mitigates': 'reverse'
        },
        "intrusion-set": {
            "uses": "reverse"
        },
        "malware": {
            "uses": "reverse"
        },
        "threat-actor": {
            "uses": "reverse"
        },
        'course-of-action': {
            'mitigates': 'reverse'
        },
        'identity': {
            'targets': 'forward'
        },
        'indicator': {
            'indicates': 'reverse'
        },
        'vulnerability': {
            'targets': 'forward'
        }
    },
    'vulnerability': {
        "attack-pattern": {
            "targets" : "reverse"
        },
        "campaign" : {
            "targets" : "reverse"
        },
        'course-of-action': {
            'mitigates': 'reverse'
        },
        "intrusion-set" : {
            "targets" : "reverse"
        },
        "malware" : {
            "targets" : "reverse"
        },
        "threat-actor" : {
            "targets" : "reverse"
        },
        "tool" : {
            "targets" : "reverse"
        }
    },
    #'report': {
    #    'threat-actor': {
    #        'related-to': 'reverse'
    #    }
    #},
    'observed-data': {
        'threat-actor': {
            'related-to': 'reverse'
        }
    }
}

#vocabulary for CybOX
HASH_ALGO_OV = [
    'MD5',
    'MD6',
    'RIPEMD160',
    'SHA1',
    'SHA224',
    'SHA256',
    'SHA384',
    'SHA512',
    'SHA3224',
    'SHA3224',
    'SHA3256',
    'SHA3256',
    'SHA3384',
    'SHA3384',
    'SHA3512',
    'SHA3512',
    'ssdeep',
    'WHIRLPOOL '
]

ENCRYPTION_ALGO_OV = [
    'AES128ECB',
    'AES128CBC',
    'AES128CFB',
    'AES128CTR',
    'AES128XTS',
    'AES128GCM',
    'Salsa20',
    'Salsa12',
    'ChaCha20Poly1305',
    'ChaCha20',
    'DESCBC',
    '3DESCBC',
    'DESEBC',
    '3DESEBC',
    'CAST128CBC',
    'CAST256CBC',
    'RSA',
    'DSA',
]

#Random data to populate generated data
RANDOM_NAMES = [
    'Rene Pauls',
    'Soraya Labombard',
    'Mariella Tincher',
    'Marlys Loveridge',
    'Louvenia Graydon',
    'Ariana Huckleberry',
    'Bell Schoenfeld',
    'Dede Hinds',
    'Lynetta Takemoto',
    'Desiree Claybrooks',
    'Anitra Sabin',
    'Rachell Gaut',
    'Hung Loden',
    'Benito Lheureux',
    'Laura Prout',
    'Allie Simon',
    'Columbus Hursh',
    'Manuela Miramontes',
    'Donnetta Schwanke',
    'Cheyenne Bonnie',
    'Sade Hane',
    'Nathanael Casillas',
    'Magaret Chartier',
    'Tasha Markey',
    'Lavelle Cowman',
    'Hae Haigler',
    'Georgianna Milici',
    ' Fausto Tseng',
    'Junita Capehart',
    'Hedwig Fishburn',
    'Latina Olmeda',
    'Annetta Estepp',
    'Audry Sheen',
    'Jolynn Denny',
    'Wallace Vero',
    'Almeda Croston',
    'Un Bellew',
    'Bobbi Sharples',
    'Ardith Cron',
    'Chrissy Mcquinn',
    'Florence Summerford',
    'Lucrecia Vanderslice',
    'Celina Mangus',
    'Rosendo Beaty',
    'Tyrone Morrisey',
    'Fanny Lockman',
    'Rhona Mansir',
    'Laveta Milledge',
    'Chad Mullen',
    'Norberto Venezia'
]


RANDOM_GIVENNAMES = [
    "Mona",
    "Peggy",
    "Noel",
    "Carrie",
    "Terry",
    "Pete",
    "Billy",
    "Cecelia",
    "David",
    "Bennie",
    "Israel",
    "Dominic",
    "Lance",
    "Gabriel",
    "Willis",
    "Agnes",
    "Lillian",
    "Douglas",
    "Gloria",
    "Anna",
    "Wanda",
    "Norman",
    "Rachael",
    "Kelly",
    "Lucas",
    "Tommie",
    "Vernon",
    "Marguerite",
    "Angie",
    "Martha",
    "Saul",
    "Eva",
    "Forrest",
    "Stewart",
    "Juan",
    "Deanna",
    "Jacqueline",
    "Margie",
    "Eddie",
    "Israel",
    "Domingo",
    "Shaun",
    "Tomas",
    "Vivian",
    "Darrin",
    "Andrew",
    "Deanna",
    "Nichole",
    "Katie",
    "Mindy",
    "Joe",
    "Brittany",
    "Derrick",
    "Leo",
    "Viola",
    "Oscar",
    "Doug",
    "Anna",
    "Brad",
    "Heather"
]

RANDOM_SURNAMES = [
    "Ellis",
    "Ballard",
    "Steele",
    "Curry",
    "Stevenson",
    "Lane",
    "Banks",
    "Diaz",
    "Powers",
    "Davis",
    "Joseph",
    "Lynch",
    "Jenkins",
    "Thompson",
    "Cunningham",
    "Holland",
    "Walters",
    "Vaughn",
    "Mccarthy",
    "Warner",
    "Pena",
    "Cook",
    "Pittman",
    "Gross",
    "Reed",
    "Montgomery",
    "Morton",
    "Mendoza",
    "Robbins",
    "Jensen",
    "Bass",
    "Bennett",
    "Briggs",
    "Anderson",
    "Sims",
    "Holt",
    "Sullivan",
    "Bowman",
    "Doyle",
    "Klein",
    "Rose",
    "Price",
    "Ramirez",
    "Benson",
    "Davidson",
    "Pena",
    "Jones",
    "Douglas",
    "Vaughn",
    "Brady",
    "Gardner",
    "Young",
    "Erickson",
    "Simmons",
    "Bradley",
    "Guzman",
    "Neal",
    "Huff",
    "Richards",
    "Hicks"
]

RANDOM_DESCRIPTIONS = [
    "Far far away, behind the word mountains, far from the countries Vokalia and Consonantia, there live the blind texts.",
    "Separated they live in Bookmarksgrove right at the coast of the Semantics, a large language ocean.",
    "A small river named Duden flows by their place and supplies it with the necessary regelialia.",
    "It is a paradisematic country, in which roasted parts of sentences fly into your mouth.",
    "Even the all-powerful Pointing has no control about the blind texts it is an almost unorthographic life One day however a small line of blind text by the name of Lorem Ipsum decided to leave for the far World of Grammar.",
    "The Big Oxmox advised her not to do so, because there were thousands of bad Commas, wild Question Marks and devious Semikoli, but the Little Blind Text didn't listen.",
    "She packed her seven versalia, put her initial into the belt and made herself on the way.",
    "When she reached the first hills of the Italic Mountains, she had a last view back on the skyline of her hometown Bookmarksgrove, the headline of Alphabet Village and the subline of her own road, the Line Lane.",
    "Pityful a rethoric question ran over her cheek, then she continued her way. On her way she met a copy.",
    "The copy warned the Little Blind Text, that where it came from it would have been rewritten a thousand times and everything that was left from its origin would be the word "and" and the Little Blind Text should turn around and return to its own, safe country.",
    "But nothing the copy said could convince her and so it didn't take long until a few insidious Copy Writers ambushed her, made her drunk with Longe and Parole and dragged her into their agency, where they abused her for their projects again and again.",
    "And if she hasn't been rewritten, then they are still using her. Far far away, behind the word mountains, far from the countries Vokalia and Consonantia, there live the blind texts.",
    "Separated they live in Bookmarksgrove right at the coast of the Semantics, a large language ocean.",
    "A small river named Duden flows by their place and supplies it with the necessary regelialia. It is a paradisematic country, in which roasted parts of sentences fly into your mouth.",
    "Even the all-powerful Pointing has no control about the blind texts it is an almost unorthographic life One day however a small line of blind text by the name of Lorem Ipsum decided to leave for the far World of Grammar.",
    "The Big Oxmox advised her not to do so, because there were thousands of bad Commas, wild Question Marks and devious Semikoli, but the Little Blind Text didn't listen.",
    "She packed her seven versalia, put her initial into the belt and made herself on the way.",
    "When she reached the first hills of the Italic Mountains, she had a last view back on the skyline of her hometown Bookmarksgrove, the headline of Alphabet Village and the subline of her own road, the Line Lane.",
    "Pityful a rethoric question ran over her cheek, then she continued her way. On her way she met a copy.",
    "The copy warned the Little Blind Text, that where it came from it would have been rewritten a thousand times and everything that was left from its origin would be the word "and" and the Little Blind Text should turn around and return to its own, safe country. But nothing the copy said could convince her and so it didn't take long until a few insidious Copy Writers ambushed her, made her drunk"
]

RANDOM_ALIASES = [
    "Acid",
    "Fury",
    "Flash",
    "Vagabond",
    "Gloom",
    "Myth",
    "Blade",
    "Aspect",
    "Duckling",
    "Plague",
    "Maestro",
    "Zero",
    "Blazer",
    "Neurosis",
    "Boggle",
    "Viper",
    "Enigma",
    "Impossible",
    "Dread",
    "Veil",
    "Duckling",
    "Grin",
    "Wrath",
    "Sage",
    "Nightmare",
    "Paradox",
    "Phoenix",
    "Scepter",
    "Flinch",
    "Nightmare",
    "Doppelganger",
    "Essence",
    "Lightning",
    "Dagger",
    "Zero",
    "Paragon",
    "Torpedo",
    "Oddity"
]
DEFAULT_KILL_PHASES = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command-and-control",
    "actions-on-objective"
]

KILL_CHAIN_NAMES = [
    "2131o23",
    "aaaaaaa",
    "123a",
    "hello",
    "d0ggy-b0n3",
    "12q3",
    "5346e43",
    "ersa3",
    "asea23",
    "12312ds",
    "214x"
]

RANDOM_WORDS = [
"sausage",
"blubber",
"pencil",
"cloud",
"moon",
"water",
"computer",
"school",
"network",
"hammer",
"walking",
"violently",
"mediocre",
"literature",
"chair",
"two",
"window",
"cords",
"musical",
"zebra",
"xylophone",
"penguin",
"home",
"dog",
"final",
"ink",
"teacher",
"fun",
"website",
"banana",
"uncle",
"softly",
"mega",
"ten",
"awesome",
"attatch",
"blue",
"internet",
"bottle",
"tight",
"zone",
"tomato",
"prison",
"hydro",
"cleaning",
"telivision",
"send",
"frog",
"cup",
"book",
"zooming",
"falling",
"evily",
"gamer",
"lid",
"juice",
"moniter",
"captain",
"bonding",
"loudly",
"thudding",
"guitar",
"shaving",
"hair",
"soccer",
"water",
"racket",
"table",
"late",
"media",
"desktop",
"flipper",
"club",
"flying",
"smooth",
"monster",
"purple",
"guardian",
"bold",
"hyperlink",
"presentation",
"world",
"national  ",
"comment",
"element",
"magic",
"lion",
"sand",
"crust",
"toast",
"jam",
"hunter",
"forest",
"foraging",
"silently",
"tawesomated",
"joshing",
"pong",
"RANDOM",
"WORD"
]
