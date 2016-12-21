from random import randint

from enums import *
from stix_generator import *
from util import Util as u

def make_cybox_object_list(objects):
    """
        Makes an object list out of cybox objects to put in a cybox container
    """

    cybox_objects = {}

    for i in range(len(objects)):
        cybox_objects[str(i)] = objects[i]

    return cybox_objects

def make_cybox_container(objects):
    """
        makes cybox container
    """

    return {
        "spec_version": "3.0",
        "objects": make_cybox_object_list(objects)
    }

def make_cybox_object(ctype, desc = "", extended_properties = {}):
    """
        makes a cybox object (that goes in cybox list then container)
    """

    cybox_object = {}

    cybox_object["type"] = ctype
    cybox_object['description'] = desc
    cybox_object['extended_properties'] = extended_properties


    return cybox_object

def make_extended_properties(extensions = []):
    """
        Makes an extended property for a cybox object
    """

    props = {}
    for ext in extensions:
        props.update(ext)

    return props


def make_extension(name, content):
    """
        Makes extensions for cybox objects
    """

    return {name: content}

def make_type(ttype):
    """
        Makes an object with custom type
    """
    return {"type": ttype}

def make_file_object(file_name = "", description = "", hashes = {}, size = 0, file_name_enc = "",
            file_name_bin = "", magic_number = -1, mime_type = "", created = u.getcurrenttime(),
            modified = u.getcurrenttime(), accessed = u.getcurrenttime(),
            parent_directory_ref = "", is_encrypted = False, encryption_algorithm = "",
            decryption_key = "", contains_refs = "", file_content_ref = "", extended_properties = {}):

    """
        make an object of type file
    """

    cybox_object = make_cybox_object('file', description, extended_properties)
    cybox_object['file_name'] = file_name
    cybox_object['hashes'] = hashes
    cybox_object['size'] = size
    cybox_object['file_name_enc'] = file_name_enc
    cybox_object['file_name_bin'] = file_name_bin
    cybox_object['magic_number'] = magic_number
    cybox_object['mime_type'] = mime_type
    cybox_object['created'] = created
    cybox_object['modified'] = modified
    cybox_object['accessed'] = accessed
    cybox_object['parent_directory_ref'] = parent_directory_ref
    cybox_object['is_encrypted'] = is_encrypted
    cybox_object['encryption_algorithm'] = encryption_algorithm
    cybox_object['decryption_key'] = decryption_key
    cybox_object['contains_refs'] = contains_refs
    cybox_object['file_content_ref'] = file_content_ref

    return cybox_object

def make_ntfs_file_ext(sid = "", alternate_data_streams = []):
    """
        extention to make_file, makes ntfs file extensions
    """

    content = {}
    content['sid'] = sid
    content['alternate_data_streams'] = alternate_data_streams

    return make_extension("ntfs-ext", content)


def make_raster_img_file_ext(image_height = -1, image_width = -1, bits_per_pixel = -1, image_compression_algorithm = "", exif_tags = {}):
    """
        extention to make_file, makes raster image file extensions
    """

    content = {}
    content['image_height'] = image_height
    content['image_width'] = image_width
    content['bits_per_pixel'] = bits_per_pixel
    content['image_compression_algorithm'] = image_compression_algorithm
    content['exif_tags'] = exif_tags

    return make_extension("ntfs-ext", content)

#TODO file extensions

def make_alternate_data_stream_type(name, size = -1, hashes = ""):
    """
        makes alternate_data_stream objects for ntfs-ext
    """

    ttype = make_type("alternate_data_streams")
    ttype['name'] = name
    ttype['size'] = size
    ttype['hashes'] = hashes

    return ttype

def make_directory_object(path, description = "", path_enc = "", path_bin = "", created = u.getcurrenttime(addition = -1000), modified = u.getcurrenttime(), accessed = u.getcurrenttime(), contains_refs = [], extended_properties = {}):
    """
        makes directory object
    """
    cybox_object = make_cybox_object('directory', description, extended_properties)
    cybox_object['path'] = path
    cybox_object['path_enc'] = path_enc
    cybox_object['path_bin'] = path_bin
    cybox_object['created'] = created
    cybox_object['modified'] = modified
    cybox_object['accessed'] = accessed
    cybox_object['contains_refs'] = contains_refs

    return cybox_object

def make_win_reg_key_object(key, description = "", values = [], modified = u.getcurrenttime(), created_by_ref = "", number_of_subkeys = -1, extended_properties = {}):
    """
        makes windows-registry-key object
    """

    cybox_object = make_cybox_object('windows-registry-key', description, extended_properties)
    cybox_object['key'] = key
    cybox_object['description'] = description
    cybox_object['values'] = values
    cybox_object['modified'] = modified
    cybox_object['created_by_ref'] = created_by_ref
    cybox_object['number_of_subkeys'] = number_of_subkeys

    return cybox_object

#TODO registry key value, windows-registry-data-type-cv

def make_mutex_object(name, description = "", extended_properties = {}):
    """
        makes mutex object
    """

    cybox_object = make_cybox_object('mutex', description, extended_properties)
    cybox_object['name'] = name

    return cybox_object

def  make_x509_cert_object(description = "", is_self_signed = False, hashes = {}, version = "1.0", serial_number = "", signature_algorithm = "", issuer = "", validity_not_before = u.getcurrenttime(), validity_not_after = u.getcurrenttime(addition = 100000), subject = "", subject_public_key_modulus = "", subject_public_key_exponent = -1, x509_v3_extensions = "", extended_properties = {}):
    """
        makes x509 certificate object
    """

    cybox_object = make_cybox_object('mutex', description, extended_properties)
    cybox_object['is_self_signed'] =  is_self_signed
    cybox_object['hashes'] = hashes
    cybox_object['version'] = version
    cybox_object['serial_number'] = serial_number
    cybox_object['signature_algorithm'] = signature_algorithm
    cybox_object['issuer'] = issuer
    cybox_object['validity_not_before'] = validity_not_before
    cybox_object['validity_not_after'] = validity_not_after
    cybox_object['subject'] = subject
    cybox_object['subject_public_key_modulus'] = subject_public_key_modulus
    cybox_object['subject_public_key_exponent'] = subject_public_key_exponent
    cybox_object['x509_v3_extensions'] = x509_v3_extensions

    return cybox_object

#TODO x509 v3 ext type

def make_software_object(name, description = "", language = "", vendor = "", version = "", swid = "", extended_properties = {}):
    """
        makes a software object
    """

    cybox_object = make_cybox_object('software', description, extended_properties)
    cybox_object['name'] = name
    cybox_object['language'] = language
    cybox_object['vendor'] = vendor
    cybox_object['version'] = version
    cybox_object['swid'] = swid

    return cybox_object

def make_artifact_object(description = "", mime_type = "", payload = "", url = "", hashes={},extended_properties = {}):
    """
        makes an artitifact object
    """

    cybox_object = make_cybox_object('artifact', description, extended_properties)
    cybox_object['mime_type'] = mime_type
    cybox_object['payload'] = payload
    cybox_object['url'] = url
    cybox_object['hashes'] = hashes
    return cybox_object

def make_process_object(description = "", is_hidden = False, pid = -1, name = "", created = u.getcurrenttime(), cwd = "", arguments = [], environment_variables = {}, opened_connection_refs = [], creator_user_ref = "", binary_ref = "", parent_ref = "", child_refs = [], extended_properties = {}):
    """
        makes a process object
    """

    cybox_object = make_cybox_object('process', description, extended_properties)
    cybox_object['is_hidden'] = is_hidden
    cybox_object['pid'] = pid
    cybox_object['name'] = name
    cybox_object['created'] = created
    cybox_object['cwd'] = cwd
    cybox_object['arguments'] = arguments
    cybox_object['environment_variables'] = environment_variables
    cybox_object['opened_connection_refs'] = opened_connection_refs
    cybox_object['creator_user_ref'] = creator_user_ref
    cybox_object['binary_ref'] = binary_ref
    cybox_object['parent_ref'] = parent_ref
    cybox_object['child_refs'] = child_refs


    return cybox_object

#TODO windows process ext, windows service + vocab,

def make_user_account_object(user_id, description = "", account_login = "", account_type = "", display_name = "", is_service_account = False, is_privileged = False, can_escalate_privs = False, is_disabled = False, account_created = u.getcurrenttime(addition = -10000), account_expires = u.getcurrenttime(addition = 10000), password_last_changed = u.getcurrenttime(), account_first_login = u.getcurrenttime(), account_last_login = u.getcurrenttime(), extended_properties = {}):
    """
        makes a user account object
    """

    cybox_object = make_cybox_object('mutex', description, extended_properties)
    cybox_object['user_id'] = user_id
    cybox_object['account_login'] = account_login
    cybox_object['account_type'] = account_type
    cybox_object['display_name'] = display_name
    cybox_object['is_service_account'] = is_service_account
    cybox_object['is_privileged'] = is_privileged
    cybox_object['can_escalate_privs'] = can_escalate_privs
    cybox_object['is_disabled'] = is_disabled
    cybox_object['account_created'] = account_created
    cybox_object['account_expires'] = account_expires
    cybox_object['password_last_changed'] = password_last_changed
    cybox_object['account_first_login'] = account_first_login
    cybox_object['account_last_login'] = account_last_login

    return cybox_object

#TODO vocab, UNIX ext,

def make_ip4v_addr_object(value, description = "", resolves_to_refs = [], belongs_to_refs = [], extended_properties = {}):
    """
        makes ipv4 object
    """

    cybox_object = make_cybox_object("ipv4-addr", description, extended_properties)
    cybox_object['value'] = value
    cybox_object['resolves_to_refs'] = resolves_to_refs
    cybox_object['belongs_to_refs'] = belongs_to_refs

    return cybox_object

def make_ip6v_addr_object(value, description = "", resolves_to_refs = [], belongs_to_refs = [], extended_properties = {}):
    """
        makes ipv6 object
    """

    cybox_object = make_cybox_object("ipv6-addr", description, extended_properties)
    cybox_object['value'] = value
    cybox_object['resolves_to_refs'] = resolves_to_refs
    cybox_object['belongs_to_refs'] = belongs_to_refs

    return cybox_object

def make_mac_addr_object(value, description = "", extended_properties = {}):
    """
        make mac address object
    """
    cybox_object = make_cybox_object("mac-addr", description, extended_properties)
    cybox_object['value'] = value

    return cybox_object

def make_email_addr_object(value, description = "", display_name = "", belongs_to_refs = [], extended_properties = {}):
    """
        makes email object
    """

    cybox_object = make_cybox_object("email-addr", description, extended_properties)
    cybox_object['value'] = value
    cybox_object['display_name'] = display_name
    cybox_object['belongs_to_refs'] = belongs_to_refs

    return cybox_object

def make_url_object(value, description = "", extended_properties = {}):
    """
        makes url object
    """
    cybox_object = make_cybox_object("url", description, extended_properties)
    cybox_object['value'] = value

    return cybox_object

def make_domain_name_object(value, description = "", resolves_to_refs = [], extended_properties = {}):
    """
        makes domain object
    """
    cybox_object = make_cybox_object("domain-name", description, extended_properties)
    cybox_object['value'] = value
    cybox_object['resolves_to_refs'] = resolves_to_refs

    return cybox_object

def make_as_object(number, description = "", name = "", rir = "", extended_properties = {}):
    """
        makes autonomous-system object
    """
    cybox_object = make_cybox_object("autonomous-system", description, extended_properties)
    cybox_object['number'] = number
    cybox_object['name'] = name
    cybox_object['rir'] = rir

    return cybox_object

def make_net_traffic_object(value, description = "", start = u.getcurrenttime(), end = u.getcurrenttime(addition = 10000), is_active = True, src_ref = "", dst_ref = "", src_port = -1, dst_port = -1, protocols = [], src_byte_count = -1, dst_byte_count = -1, src_packets = -1, dst_packets = -1, ipfix = {}, src_payload_ref = "", dst_payload_ref = "", encapsulates_refs = "", encapsulated_by_ref = "", extended_properties = {}):
    """
        makes new traffic object
    """

    cybox_object = make_cybox_object("network-traffic", description, extended_properties)
    cybox_object['value'] = value
    cybox_object['end'] = end
    cybox_object['is_active'] = is_active
    cybox_object['src_ref'] = src_ref
    cybox_object['dst_ref'] = dst_ref
    cybox_object['src_port'] = src_port
    cybox_object['dst_port'] = dst_port
    cybox_object['protocols'] = protocols
    cybox_object['src_byte_count'] = src_byte_count
    cybox_object['dst_byte_count'] = dst_byte_count
    cybox_object['src_packets'] = src_packets
    cybox_object['dst_packets'] = dst_packets
    cybox_object['ipfix'] = ipfix
    cybox_object['src_payload_ref'] = src_payload_ref
    cybox_object['dst_payload_ref'] = dst_payload_ref
    cybox_object['encapsulates_refs'] = encapsulates_refs
    cybox_object['encapsulated_by_ref'] = encapsulated_by_ref

    return cybox_object


#TODO HTTP Extension, TCP Extension, ICMP ext, net socket ext,

def make_email_msg__object(is_mulyipart, description = "", date = u.getcurrenttime(addition = -1000), content_type = "", from_ref = "", sender_ref = "", to_ref = "", cc_refs = "", bcc_refs = "", subject = "", received_lines = [], additional_header_fields = {}, body = "", body_multipart = False, raw_email_ref = "", extended_properties = {}):
    """
        makes email message object
    """

    cybox_object = make_cybox_object("email-message", description, extended_properties)
    cybox_object['is_mulyipart'] = is_mulyipart
    cybox_object['date'] = date
    cybox_object['content_type'] = content_type
    cybox_object['from_ref'] = from_ref
    cybox_object['sender_ref'] = sender_ref
    cybox_object['o_ref'] = to_ref
    cybox_object['cc_refs'] = cc_refs
    cybox_object['bcc_refs'] = bcc_refs
    cybox_object['subject'] = subject
    cybox_object['received_lines'] = received_lines
    cybox_object['additional_header_fields'] = additional_header_fields
    cybox_object['body'] = body
    cybox_object['body_multipart'] = body_multipart
    cybox_object['raw_email_ref'] = raw_email_ref

    return cybox_object

def generate_pattern_eq_ipv4_list(ips):
    """
        makes makes a pattern that detects a list of patterns
    """

    pattern = ""

    for ip in ips:
        pattern += generate_pattern_eq_ipv4(ip)
        if ip is not ips[len(ips) - 1]:
            pattern += " OR "

    return pattern


def generate_pattern_eq_ipv4(value):
    """
        makes a pattern to check an ip address
    """
    return "ipv4-addr:value = '" + value + "'"

def generate_dummy_ip():
    """
        makes a random ip address as a string
    """
    return str(randint(0,255)) + "." + str(randint(0,255)) + "." + str(randint(0,255)) + "." + str(randint(0,255))

def generate_random_ip_list(count = randint(10, 30)):
    """
        makes a list of random ip addresses
    """
    ips = []

    for i in range(0, count):
        ips.append(generate_dummy_ip())
    return ips



def generate_tardis_cybox():
    """
        A test container maker function
    """
    cy = make_file_object("cybox_generator.py", "cybox generating python script", size = 4021)
    co = [
        make_directory_object('c://Users/TheDoctor/'),
        make_file_object('tardis.exe', hashes = {"md5":"B4D33B0C7306351B9ED96578465C5579"}, parent_directory_ref = "0", extended_properties = make_extended_properties([make_ntfs_file_ext("as", [make_alternate_data_stream_type("second.stream", 25543)])]))
    ]

    for o in co:
        o = u.clean_dict(o)

    cc = make_cybox_container(co)

    return cc

#TODO verify that this pattern generation system validates
def finish_pattern(pattern):
    """
        pattern functions only make the inside stuff, so this finished

    """
    return '[' + pattern + ']'

def main():
    print finish_pattern(generate_pattern_eq_ipv4_list(generate_random_ip_list(10)))


if __name__ == "__main__":
    main()
