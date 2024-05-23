import json
import argparse
import os
import numpy as np
from parse import parse
from glob import glob
from typing import List, Dict
from progressbar import ProgressBar
import pandas as pd
import json
import re
import matplotlib.pyplot as plt


INITIAL_TRUST = 0.5
AGING_FACTOR = 0.5


def vehicleParser(json_file, path_to_json,attacker_dict_ground_truth):
    log_name_tokens = os.path.splitext(json_file)[0].split("-")
    vehicle_id = log_name_tokens[1]  # [0]:= 'JSONlog' [1]:=vehicle instance count [2]:=vehicle id [1]:=vehicle attack type
    vehicle_OMNET_ID = log_name_tokens[2]  # [0]:= 'JSONlog' [1]:=vehicle instance count [2]:=vehicle id [1]:=vehicle attack type

    attack_type = log_name_tokens[3]
    if attack_type == 'A0':
        is_vehicle_attacker = 0
    else:
        is_vehicle_attacker = 1

    # check the ground truth file as well, override the filename labels if there is ground truth record
    #if int(vehicle_id) in attacker_dict_ground_truth.keys():
    #    is_vehicle_attacker = attacker_dict_ground_truth[int(vehicle_id)]

    # start parsing the file
    BSMList = [] # received BSM messages
    GPSList=[] # own gps messages

    file_path = os.path.join(path_to_json, json_file)
    with open(file_path, "r") as f:
        log_rows = f.readlines()

    for row in log_rows:
        json_row = json.loads(row)
        json_row['vehicle_ID'] = vehicle_id  # set here, change later
        # json_row['vehicle_OMNET_ID'] = vehicle_OMNET_ID
        json_row['is_attacker'] = is_vehicle_attacker
        if json_row['type'] == 2: # discard the self GPS messages
            # gps_row = json_row

            # extract position
            json_row['pos_x'] = json_row['pos'][0]
            json_row['pos_y'] = json_row['pos'][1]
            #json_row['pos_z'] = json_row['pos'][2]
            del json_row['pos']

            # extract speed
            json_row['spd_x'] = json_row['spd'][0]
            json_row['spd_y'] = json_row['spd'][1]
            #json_row['spd_z'] = json_row['spd'][2]
            del json_row['spd']

            # extract position noise
            #json_row['pos_x_noise'] = json_row['pos_noise'][0]
            #json_row['pos_y_noise'] = json_row['pos_noise'][1]
            #json_row['pos_z_noise'] = json_row['pos_noise'][2]
            del json_row['pos_noise']

            # extract spd noise
            # json_row['spd_x_noise'] = json_row['spd_noise'][0]
            # json_row['spd_y_noise'] = json_row['spd_noise'][1]
            # json_row['spd_z_noise'] = json_row['spd_noise'][2]
            del json_row['spd_noise']

            # Acceleration
            json_row['accel_x'] = json_row['acl'][0]
            json_row['accel_y'] = json_row['acl'][1]
            #json_row['accel_z'] = json_row['acl'][2]
            del json_row['acl']

            # Heading
            json_row['heading_x'] = json_row['hed'][0]
            json_row['heading_y'] = json_row['hed'][1]
            #json_row['heading_z'] = json_row['hed'][2]
            del json_row['hed']

            # remove unnecessary columns
            del json_row['acl_noise']
            del json_row['type']
            del json_row['hed_noise']

            # add new dict to list
            GPSList.append(json_row)

        else:

            # extract position
            json_row['pos_x'] = json_row['pos'][0]
            json_row['pos_y'] = json_row['pos'][1]
            #json_row['pos_z'] = json_row['pos'][2]
            del json_row['pos']


            # extract speed
            json_row['spd_x'] = json_row['spd'][0]
            json_row['spd_y'] = json_row['spd'][1]
            #json_row['spd_z'] = json_row['spd'][2]
            del json_row['spd']

            # extract position noise
            #json_row['pos_x_noise'] = json_row['pos_noise'][0]
            #json_row['pos_y_noise'] = json_row['pos_noise'][1]
            #json_row['pos_z_noise'] = json_row['pos_noise'][2]
            del json_row['pos_noise']

            # extract spd noise
            #json_row['spd_x_noise'] = json_row['spd_noise'][0]
            #json_row['spd_y_noise'] = json_row['spd_noise'][1]
            #json_row['spd_z_noise'] = json_row['spd_noise'][2]
            del json_row['spd_noise']


            # Acceleration
            json_row['accel_x'] = json_row['acl'][0]
            json_row['accel_y'] = json_row['acl'][1]
            #json_row['accel_z'] = json_row['acl'][2]
            del json_row['acl']


            # Heading
            json_row['heading_x'] = json_row['hed'][0]
            json_row['heading_y'] = json_row['hed'][1]
            #json_row['heading_z'] = json_row['hed'][2]
            del json_row['hed']


            # remove unnecessary columns
            del json_row['acl_noise']
            del json_row['sendTime']
            del json_row['type']
            #del json_row['senderPseudo']
            del json_row['messageID']
            del json_row['hed_noise']

            # add new dict to list
            BSMList.append(json_row)



    # creat gps df
    GPS_df = pd.DataFrame(GPSList)
    if not GPS_df.empty:
        GPS_df = GPS_df.sort_values(["rcvTime"])

    # create bsm df
    BSM_df = pd.DataFrame(BSMList)
    if not BSM_df.empty:
        BSM_df = BSM_df.sort_values(["senderPseudo", "rcvTime"])


    # trust_dict= assignTrust(BSM_df=BSM_df,GPS_df=GPS_df)

    return BSM_df

def plausibilityParser(vehicle_ID,vehicle_plausibility_record):

    file_path =vehicle_plausibility_record
    f = open(file_path, )

    data = json.load(f)

    data_list = []
    for row in data:
        json_row = {}

        json_row['vehicle_ID'] = vehicle_ID  # set here, change later

        json_row['sender'] = row['BsmPrint']['BSMs'][0]['RealId']

        json_row['rcvTime'] = row['BsmPrint']['BSMs'][0]['ArrivalTime']

        json_row['proximityPlausibility'] = row['BsmPrint']['BsmCheck']['rpP']

        json_row['rangePlausibility'] = row['BsmPrint']['BsmCheck']['rP']

        json_row['PositionPlausibility'] = row['BsmPrint']['BsmCheck']['pP']

        json_row['SpeedPlausibility'] = row['BsmPrint']['BsmCheck']['sP']

        json_row['PositionConsistancy'] = row['BsmPrint']['BsmCheck']['pC']

        json_row['SpeedConsistancy'] = row['BsmPrint']['BsmCheck']['sC']

        json_row['PositionSpeedConsistancy'] = row['BsmPrint']['BsmCheck']['psC']

        json_row['PositionSpeedMaxConsistancy'] = row['BsmPrint']['BsmCheck']['psmC']

        json_row['PositionHeadingConsistancy'] = row['BsmPrint']['BsmCheck']['phC']

        json_row['SuddenAppearence'] = row['BsmPrint']['BsmCheck']['sA']

        json_row['BeaconFrequency'] = row['BsmPrint']['BsmCheck']['bF']

        json_row['senderPseudo'] = row['BsmPrint']['BSMs'][0]['Pseudonym']

        data_list.append(json_row)



    # create bsm df
    BSM_df = pd.DataFrame(data_list)
    if not BSM_df.empty:
        BSM_df = BSM_df.sort_values(["senderPseudo", "rcvTime"])

    return BSM_df

def vehicleIDfromPlausibility(filename):

    name_components = re.split('_', os.path.splitext(filename)[0])

    vehicle_ID = name_components[2]


    # remove first "10" and last "1" to get the real ID of vehicles
    vehicle_ID =vehicle_ID[2:]
    vehicle_ID=vehicle_ID[:-1]

    return vehicle_ID

def parsePlausibilityRecords(plausibility_path):

    vehicle_records= os.listdir(plausibility_path)
    big_df = pd.DataFrame()


    for vehicle_plausibility_record in vehicle_records:

        vehicle_ID = vehicleIDfromPlausibility(vehicle_plausibility_record)

        cur_file = os.path.join(plausibility_path,vehicle_plausibility_record)
        parsed_df = plausibilityParser(vehicle_ID,cur_file)
        big_df = pd.concat([big_df, parsed_df], axis=0, ignore_index=True)


    return big_df

def mergePlausibility(plausibility_records,BSM_records):

    # from the beginning of time step
    plausibility_records['rcvTime'] = plausibility_records['rcvTime'].apply(np.floor)
    BSM_records['rcvTime'] = BSM_records['rcvTime'].apply(np.floor)

    trust_records = createTrustRecords(plausibility_records)

    all_data = pd.merge(BSM_records, trust_records, how='left', left_on=['vehicle_ID', 'senderPseudo', 'rcvTime'], right_on=['vehicle_ID', 'senderPseudo', 'rcvTime'])

    return all_data

    pass

def calculateTrust(sender,receiver,messages):

    considered_modules = ["rangePlausibility", "PositionConsistancy", "SpeedConsistancy",
                          "PositionSpeedConsistancy", "PositionHeadingConsistancy"]

    num_modules = len(considered_modules)
    module_weights = [1/num_modules]*num_modules # equal weights for all for now
    initial_trust= INITIAL_TRUST
    aging_factor = AGING_FACTOR


    # sort by message receiving time for time-based records
    trust_records = {}

    for index,row in messages.iterrows():
        cur_time = row['rcvTime']

        # find the prev trust
        if trust_records.keys() and (min(trust_records.keys())) < cur_time:

            # previous record exists, find the latest record
            max_time = max(trust_records.keys())
            prev_trust = trust_records[max_time]
        else:

            # no records exist
            prev_trust= initial_trust

        ## calculate the current step trust contribution
        current_step_score = 0
        for i,module in enumerate(considered_modules):
            current_step_score += module_weights[i] * row[module]

        # age the trust
        eventual_trust = aging_factor*prev_trust + (1-aging_factor) * current_step_score
        trust_records[cur_time] = eventual_trust



    # convert to data frame and merge
    trust_df = pd.DataFrame.from_dict(trust_records, orient='index',
                           columns=['Trust'])
    trust_df['rcvTime'] =trust_df.index
    trust_df.sort_values(['rcvTime'])

    new_messages = pd.merge(messages, trust_df, how='left', left_on=['rcvTime'], right_on=['rcvTime'])


    return new_messages

def trustEvolutionForReceiver(receiver_ID,records):

    sender_list = records['senderPseudo'].unique()
    g = records.groupby(["senderPseudo"])

    big_df = pd.DataFrame()

    for sender in sender_list:
        sender_records = g.get_group(sender)

        trust_records = calculateTrust(sender=sender,receiver=receiver_ID,messages=sender_records)
        pass

        big_df = pd.concat([big_df, trust_records], axis=0, ignore_index=True)

    return big_df

def createTrustRecords(plausibility_records):
    receiver_vehicles = plausibility_records['vehicle_ID'].unique()
    g = plausibility_records.groupby(['vehicle_ID'])

    big_df = pd.DataFrame()

    for receiver_vehicle in receiver_vehicles:
        current_records = g.get_group(receiver_vehicle)
        receiver_trust = trustEvolutionForReceiver(receiver_vehicle,current_records)

        big_df = pd.concat([big_df, receiver_trust], axis=0, ignore_index=True)


    return big_df



def parseSim(data_folder,output_path):

    folder_list = os.listdir(data_folder)

    for folder in folder_list:
        if "MDBsmsList" in folder:
            plausibility_path = os.path.join(data_folder,folder)
        if "VeReMi" in folder:
            path_to_json = os.path.join(data_folder,folder)


    plausibility_records = parsePlausibilityRecords(plausibility_path=plausibility_path)

    """Find the json files"""

    json_files = [pos_json for pos_json in os.listdir(path_to_json) if
                  (pos_json.endswith('.json') and pos_json.startswith('traceJSON'))]

    ground_truth_file_path = [pos_json for pos_json in os.listdir(path_to_json) if
                              (pos_json.endswith('.json') and pos_json.startswith('traceGroundTruth'))]


    # start parsing

    big_df = pd.DataFrame()

    for json_file in json_files:
        parsed_df = vehicleParser(json_file, path_to_json,
                                  {})  # .sort_values(["sender","rcvTime"])
        big_df = pd.concat([big_df, parsed_df], axis=0, ignore_index=True)




    big_df = mergePlausibility(plausibility_records=plausibility_records,BSM_records=big_df)

    # drop noise columns before saving
    big_df.drop(list(big_df.filter(regex="noise")), axis=1, inplace=True)
    if 'sender_x' in big_df.columns:
        big_df.rename(columns={"sender_x": "sender"}, inplace=True)
        big_df.drop(['sender_y'], axis=1, inplace=True)

    # make the export file name
    dir_lst = data_folder.split(sep="/")
    exportfilename=os.path.join(output_path,dir_lst[1] + "_" + "parsed.csv")
    big_df.to_csv(index=False, path_or_buf=exportfilename)

    return big_df


def findAndParseAllData(sim_path,num_cases,output_path):
    from functools import partial
    from multiprocessing import Pool

    test_folders = os.listdir(sim_path)

    for i, folder in enumerate(test_folders):
        test_folders[i] = os.path.join(sim_path, folder)


    # Create the pool and start parsing
    func = partial(parseSim, output_path=output_path)
    pool = Pool()
    pool.map(func, test_folders)
    pool.close()
    pool.join()

    print("DONE!")
    return True




if __name__ == '__main__':

    sim_path = "raw_logs/" # raw data path
    num_cases = 2
    output_path ="parsed_logs/"
    findAndParseAllData(sim_path,num_cases,output_path)
