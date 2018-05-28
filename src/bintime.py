#!/usr/bin/env python3
import argparse
import collections
import hashlib
import json
import logging
import os
import pefile
import time
import webbrowser

from os import listdir
from os.path import isfile, join

# STATIC VARIABLES
BINTIME_DESCRIPTION = "This is a script that will enumerate timestamps associated with binary files"
TIMELINE_TEMPLATE_LOCATION = "timeline_template.html"


# Initiate Logger
log = logging.getLogger("bintime-logger")

def main():
    '''
    Main functionality of bintime
    '''
    sorted_time_list = collections.OrderedDict()
    
    #List to generate timeline
    timeline_list = []

    # Retrieve and build script arguments
    parser = argparse.ArgumentParser(description=BINTIME_DESCRIPTION)
    parser.add_argument("input", help="file or directory to run bintime against")
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                    action="store_true")
    parser.add_argument("-t", "--timeline", help="create a timeline from input",
                    action="store_true")
    parser.add_argument("-f", "--full", help="output will display all timestamps",
                    action="store_true")
    args = parser.parse_args()

    # Determine if we should print logging info to std.out
    if args.verbose:
        logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))

    log.info("Starting BinTime...")
    
    if not args.input:
        log.error("No input file provided {}".format(input))

    file_list = parse_input(args.input)
    log.info("found the following files => {}".format(file_list))

    for idx, pe_file in enumerate(file_list):
        alert_list = []
        log.info("Processing {} via bintime".format(pe_file))
        if os.path.isfile(pe_file):
            time_list = extract_pe_timestamps(pe_file)
            hash = generate_file_hash(pe_file)
            log.info("Generated {} hash: {}".format(pe_file, hash))
            atime = time.localtime(os.path.getatime(pe_file))
            time_list.update({"[ACCESS_TIME]":atime})
            log.info("Collected {} accessed time: {}".format(hash, print_time(atime)))
            ctime = time.localtime(os.path.getctime(pe_file))
            time_list.update({"[CREATE_TIME]":ctime})
            log.info("Collected {} create time: {}".format(hash, print_time(ctime)))
            mtime = time.localtime(os.path.getmtime(pe_file))
            time_list.update({"[MODIFIED_TIME]":mtime})
            log.info("Collected {} modification time: {}".format(hash, print_time(mtime)))
        else:
            log.error("{} is not a file!".format(pe_file))
            pass

        #Checks for possible time stomping and/or borland compiled files, then omits them from range
        sorted_time_list = sorted(time_list, key=time_list.__getitem__)
        item_num = 0
        try:
            if time_list['IMAGE_FILE_HEADER'] == time.localtime(708992537):
                log.info("Borland timestamp found on {}, omitting from range".format(hash))
                alert_list.append("Borland timestamp found on {}! (This timedatestamp will not be included in range)\n".format(hash))
                item_num = 1
            elif (time_list['IMAGE_FILE_HEADER'] > sorted_time_list[0]):
                log.info("Possible timestomping found on {}, omitting from range".format(hash))
                alert_list.append("Possible timestomp of {} found on {}! (This timedatestamp will not be included in range)\n"
                    .format(print_time(time_list['IMAGE_FILE_HEADER']), hash))
        except:
            log.info("file {} may not have a compile time".format(hash))

        start_time = time_list[sorted_time_list[item_num]]
        end_time = time_list[sorted_time_list[-1]]
        log.info("Time range found from: {} to {}".format(print_time(start_time), print_time(end_time)))

        if args.timeline:
            log.info("Adding the following item to timeline => {{id: {}, content: '{}', start: '{}', end: '{}', title: '{}'}},"
                .format(idx, hash, print_time(start_time), print_time(end_time), pe_file.split("/")[-1]))
            timeline_list.append("{{id: {}, content: '{}', start: '{}', end: '{}', title: '{}'}}"
                .format(idx, hash, print_time(start_time), print_time(end_time), pe_file.split("/")[-1]))

        print(print_record(pe_file, hash, alert_list, start_time, end_time, time_list, args))
        
    if args.timeline:
        fname = generate_timeline_html(timeline_list, pe_file)
        log.info("Opening webbrowser to ()".format(fname))
        webbrowser.open('file://' + os.path.realpath(fname))

def print_time(time_stamp):
    '''
    Converts timestamp for formatted string
    '''
    return(time.strftime('%Y-%m-%d %H:%M:%S', time_stamp))

def print_record(pe_file, hash, alert_list, start_time, end_time, time_list, args):
    '''
    Will generate the standard output for this script
    '''
    std_output = '''
    ======================\n
    Filename: {}\n
    Checksum (md5): {}\n\n'''.format(pe_file.split("/")[-1], hash)
    if alert_list:
        std_output += '''    -----------------[Alerts]----------------\n
    {}'''.format(''.join(alert_list))
    std_output += '''
    ------------[Existence Range]------------\n
    Start: {}\n
    End:   {}\n
    '''.format(print_time(start_time), print_time(end_time))
    if args.full:
        std_output += '------------[All Timestamps]------------\n\n'
        for k, v in time_list.items():
            std_output += '    {} - {}\n'.format(print_time(v), k)
        std_output += '\n    ======================\n'
    else:
        std_output += '======================\n'

    return(std_output)

def parse_input(input):
    '''
    Takes the input from the CLI and returns a list of all the files bintime will run against
    '''
    file_list = []

    if os.path.isdir(input):
        log.info("{} is a directory, will run bintime against all files".format(input))
        file_list = ['{}{}'.format(input,f) for f in listdir(input) if isfile(join(input, f))]
    else:
        log.info("{} is NOT a directory, will run bintime against this input as a file".format(input))
        file_list.append(input)

    return(file_list)

def generate_file_hash(pe_file):
    '''
    Takes a file object and generates an md5 checksum for it
    '''
    hasher = hashlib.md5()
    with open(pe_file, 'rb') as hash_file:
        buf = hash_file.read()
        hasher.update(buf)
    return(hasher.hexdigest())

def generate_timeline_html(timeline_list, pe_file):
    '''
    Uses the timeline template to create a html page timeline
    '''
    #Check for template
    fname = "{}/bintime_timeline_{}.html".format('/'.join(pe_file.split('/')[:-2]),time.strftime('%Y-%m-%d-%H-%M-%S', time.gmtime()))
    try:
        html = open(TIMELINE_TEMPLATE_LOCATION).read()
    except FileNotFoundError as e:
        log.error("Unable to create timeline - {}".format(e))
        return(None)
    except IOError as e:
        log.error("Unable to open file - {}".format(e))
        return(None)
    except:
        log.error("Unexpected error! - {}".format(e))
        return(None)
    html = html.replace('[[[REPLACE]]]', ',\n'.join(timeline_list))
    try:
        with open(fname, 'w') as timeline:
            timeline.write(html)
            log.info("Created timeline using the following filename: {}".format(fname))
    except IOError as e:
        log.error("Unable to open file. {}".format(e))
        return(None)
    except:
        log.error("Unexpected error! - {}".format(e))
        return(None)
    return(fname)

def extract_pe_timestamps(pe_file):
    '''
    Extracts timestamps from all available PE structures.
    '''
    time_list = collections.OrderedDict()
    try:
        pe =  pefile.PE(pe_file)
        log.info("pe file parsing for {} was successful".format(os.path.abspath(pe_file)))
    except:
        log.error("Unable to parse PE file named {}".format(pe_file))
        return(None)
    
    for idx, entry in enumerate(pe.__structures__):
            try:
                if entry.TimeDateStamp != 0:
                    if entry.name == "IMAGE_FILE_HEADER":
                        name = entry.name
                    else:
                        name = "{}({})".format(entry.name, idx)
                    timestr = time.localtime(entry.TimeDateStamp)
                    log.info("FOUND PE TIMESTAMP => [{}] - {}".format(name, print_time(timestr)))
                    time_list.update({name:timestr})
            except:
                pass
    if time_list:
        return(time_list)
    else:
        log.error("{} returned no timestamps".format(pe_file))
        return(None)

if __name__ == "__main__":
    main()