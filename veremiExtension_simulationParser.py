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
import math
import matplotlib.pyplot as plt
import time

"""Sets the sender pseudonym as sender ID for sybil attack scenarios and protocol level attacks"""


INITIAL_TRUST = 0.5
AGING_FACTOR=0.5


def vehicleParser(json_file, path_to_json,attacker_dict_ground_truth):
    log_name_tokens = os.path.splitext(json_file)[0].split("-")
    vehicle_id = log_name_tokens[1]  # [0]:= 'JSONlog' [1]:=vehicle instance count [2]:=vehicle id [1]:=vehicle attack type
    vehicle_OMNET_ID = log_name_tokens[2]  # [0]:= 'JSONlog' [1]:=vehicle instance count [2]:=vehicle id [1]:=vehicle attack type

    attack_type = log_name_tokens[3]
    if attack_type == 'A0':
        is_vehicle_attacker = 0
    else:
        is_vehicle_attacker = 1

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
            json_row['pos_x_noise'] = json_row['pos_noise'][0]
            json_row['pos_y_noise'] = json_row['pos_noise'][1]
            #json_row['pos_z_noise'] = json_row['pos_noise'][2]
            del json_row['pos_noise']

            # extract spd noise
            json_row['spd_x_noise'] = json_row['spd_noise'][0]
            json_row['spd_y_noise'] = json_row['spd_noise'][1]
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

            # heading noise
            json_row['heading_x_noise'] = json_row['hed_noise'][0]
            json_row['heading_y_noise'] = json_row['hed_noise'][1]
            # json_row['heading_z'] = json_row['hed'][2]
            del json_row['hed_noise']



            # remove unnecessary columns
            del json_row['acl_noise']
            del json_row['type']
            #del json_row['hed_noise']

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
            json_row['pos_x_noise'] = json_row['pos_noise'][0]
            json_row['pos_y_noise'] = json_row['pos_noise'][1]
            #json_row['pos_z_noise'] = json_row['pos_noise'][2]
            del json_row['pos_noise']

            # extract spd noise
            json_row['spd_x_noise'] = json_row['spd_noise'][0]
            json_row['spd_y_noise'] = json_row['spd_noise'][1]
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


            # heading noise
            json_row['heading_x_noise'] = json_row['hed_noise'][0]
            json_row['heading_y_noise'] = json_row['hed_noise'][1]
            # json_row['heading_z'] = json_row['hed'][2]
            del json_row['hed_noise']

            # remove unnecessary columns
            del json_row['acl_noise']
            del json_row['sendTime']
            del json_row['type']
            # del json_row['senderPseudo']
            del json_row['messageID']
            #del json_row['hed_noise']

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

    return GPS_df,BSM_df

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

        data_list.append(json_row)



    # create bsm df
    BSM_df = pd.DataFrame(data_list)
    if not BSM_df.empty:
        BSM_df = BSM_df.sort_values(["sender", "rcvTime"])

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

    considered_modules= ["rangePlausibility","positionConsistency","speedConsistency","positionSpeedConsistancy","positionHeadingConsistancy"]

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
    print("Current data folder: "+data_folder)

    
    folder_list = os.listdir(data_folder)
    plausibility_path = None

    for folder in folder_list:
        if "MDBsmsList" in folder:
            plausibility_path = os.path.join(data_folder,folder)
        if "VeReMi" in folder:
            path_to_json = os.path.join(data_folder,folder)

    if plausibility_path:
        plausibility_records = parsePlausibilityRecords(plausibility_path=plausibility_path)

    else:
        # extract some plausibilties here
        pass

    """Find the json files"""

    json_files = [pos_json for pos_json in os.listdir(path_to_json) if
                  (pos_json.endswith('.json') and pos_json.startswith('traceJSON'))]

    ground_truth_file_path = [pos_json for pos_json in os.listdir(path_to_json) if
                              (pos_json.endswith('.json') and pos_json.startswith('traceGroundTruth'))]


    # json_files=json_files[:10] # remove later
    # start parsing

    big_df = pd.DataFrame()
    plausibility_records=pd.DataFrame()
    for json_file in json_files:
        GPS_df,BSM_df = vehicleParser(json_file, path_to_json,
                                  {})  # .sort_values(["sender","rcvTime"])

        if len(BSM_df)<1:
            continue # do not append anything from here


        plausibilities= createPlausibilities(GPS_df=GPS_df,BSM_df=BSM_df)

        big_df = pd.concat([big_df, BSM_df], axis=0, ignore_index=True)
        plausibility_records=pd.concat([plausibility_records,plausibilities], axis=0, ignore_index=True)


    # rename if wrong name
    if 'vehicle_ID_bsm' in plausibility_records.columns:
        plausibility_records.rename(columns={"vehicle_ID_bsm": "vehicle_ID"}, inplace=True)

    big_df = mergePlausibility(plausibility_records=plausibility_records,BSM_records=big_df)

    # drop noise columns before saving
    big_df.drop(list(big_df.filter(regex="noise")),axis=1,inplace=True)
    if 'sender_x' in big_df.columns:
        big_df.rename(columns={"sender_x": "sender"}, inplace=True)
        big_df.drop(['sender_y'],axis=1,inplace=True)


    # make the export file name
    dir_lst = data_folder.split(sep="/")
    exportfilename=os.path.join(output_path,dir_lst[1] + "_" + "parsed.csv")
    big_df.to_csv(index=False, path_or_buf=exportfilename)

    return big_df

def createPlausibilities(GPS_df,BSM_df):
    """
    Extract the palusibilities and append to BSM_df for additional features
    Args:
        GPS_df:
        BSM_df:

    Returns:

    """

    TOTAL_TIME=0
    NUM_MESSAGES=0

    MAX_PLAUSIBLE_RANGE = 420

    # get all unique senders in session
    all_senders = BSM_df['senderPseudo'].unique()

    BSM_df['rcvTime'] = BSM_df['rcvTime'].apply(np.floor)

    big_df_merged = pd.DataFrame()

    non_records = 0
    for sender in all_senders:

        sender_records = BSM_df[BSM_df['senderPseudo'] == sender]

        # align time vectors
        sliced_GPS_df= GPS_df[GPS_df.rcvTime.isin(sender_records.rcvTime)]
        merged= sender_records.merge(sliced_GPS_df,left_on='rcvTime',right_on='rcvTime',suffixes=('_bsm','_gps'))


        for index,row in merged.iterrows():

            try:
                # range plausibility
                merged.loc[index,'rangePlausibility']=rangePlausibility(sender_records.iloc[index],sliced_GPS_df.iloc[index])
            except:
                # range plausibility
                merged.loc[index, 'rangePlausibility'] = INITIAL_TRUST
                print("SYBIL,NON EXISTENT RECORD,initial trust value\n")
                non_records+=1


            if index==0:
                merged.loc[index, 'positionConsistency'] = INITIAL_TRUST #positionConsistencyCheck(row, oldRow)

                merged.loc[index, 'speedConsistency'] = INITIAL_TRUST # speedConsistencyCheck(row, oldRow)

                # position speed check
                merged.loc[index, 'positionSpeedConsistancy'] =INITIAL_TRUST # positionSpeedConsistancyCheck(row, oldRow)

                # position heading check
                merged.loc[index, 'positionHeadingConsistancy'] = INITIAL_TRUST # PositionHeadingConsistancyCheck(row, oldRow)

            else:

                oldRow =merged.loc[index-1]
                # speed and position consistency

                start = time.time()

                merged.loc[index, 'positionConsistency'] = positionConsistencyCheck(row,oldRow)

                merged.loc[index, 'speedConsistency'] = speedConsistencyCheck(row,oldRow)

                #position speed check
                merged.loc[index, 'positionSpeedConsistancy'] = positionSpeedConsistancyCheck(row, oldRow)

                # position heading check
                merged.loc[index, 'positionHeadingConsistancy'] = PositionHeadingConsistancyCheck(row, oldRow)

                end = time.time()
                current_elapsed_time = end - start
                TOTAL_TIME += current_elapsed_time
                NUM_MESSAGES+=1
                #print("Calculating trust: " + " took" + str(current_elapsed_time) + " seconds")

        #print("Average Time:" + str(TOTAL_TIME / NUM_MESSAGES))

        big_df_merged = pd.concat([big_df_merged,merged], axis=0, ignore_index=True)

    plausibilities= big_df_merged[["rcvTime","sender","senderPseudo","vehicle_ID_bsm","positionHeadingConsistancy","positionSpeedConsistancy","speedConsistency","positionConsistency","rangePlausibility"]]
    #BSM_df.reset_index(inplace=True,drop=True)
    #BSM_df=BSM_df.join(plausibilities)
    # print(non_records)
    return plausibilities #BSM_df

PI=math.pi

def PositionHeadingConsistancyCheck(row,oldRow):

    """
    (veins::Coord* curHeading,
    veins::Coord* curHeadingConfidence, veins::Coord* oldPosition,
    veins::Coord* oldPositionConfidence, veins::Coord* curPosition,
    veins::Coord* curPositionConfidence, double deltaTime, double curSpeed,
    double curSpeedConfidence):
    """

    POS_HEADING_TIME = 1.1
    MAX_HEADING_CHANGE = 90

    curHeading =calculateHeadingAngle(row)
    curHeadingConfidence=0
    oldPositionConfidence=calculatePositionConf(oldRow)
    curPositionConfidence=calculatePositionConf(row)
    deltaTime= np.abs(row.rcvTime - oldRow.rcvTime)
    curSpeed=calculateSpeedPtr(row)
    curSpeedConfidence=calculateSpeedConf(row)

    if (deltaTime < POS_HEADING_TIME):
        distance = calculateDistancePtr(row,oldRow);
        if (distance < 1):
            return 1;


        if (curSpeed - curSpeedConfidence < 1):
            return 1;


        curHeadingAngle = curHeading#calculateHeadingAnglePtr(curHeading);

        #relativePos = (curPosition->x - oldPosition->xcurPosition->y - oldPosition->y,curPosition->z - oldPosition->z);
        positionAngle = calculateHeadingAnglePtr(row.pos_x_bsm-oldRow.pos_x_bsm,row.pos_y_bsm-oldRow.pos_y_bsm);
        angleDelta = np.abs(curHeadingAngle - positionAngle);


        if (angleDelta > 180):
            angleDelta = 360 - angleDelta;


        angleLow = angleDelta - row.heading_x_noise_bsm;
        if (angleLow < 0):
            angleLow = 0;


        angleHigh = angleDelta + row.heading_x_noise_bsm;
        if (angleHigh > 180):
            angleHigh = 180;


        xLow = distance * np.cos(angleLow * PI / 180);

        curFactorLow = 1;
        if (row.heading_x_noise_bsm == 0):
            if (angleLow <= MAX_HEADING_CHANGE):
                curFactorLow = 1;

            else:
                curFactorLow = 0;


        else:
            curFactorLow =calculateCircleSegment(row.pos_x_noise_bsm,
                                                 row.pos_x_noise_bsm + xLow) /(PI * row.pos_x_noise_bsm * row.pos_x_noise_bsm);


        oldFactorLow = 1;
        if (oldRow.pos_x_noise_bsm == 0):
            if (angleLow <= MAX_HEADING_CHANGE):
                oldFactorLow = 1;

            else:
                oldFactorLow = 0;


        else:
            oldFactorLow = 1 - calculateCircleSegment(oldRow.pos_x_noise_bsm,oldRow.pos_x_noise_bsm - xLow) / (PI * oldRow.pos_x_noise_bsm * oldRow.pos_x_noise_bsm);


        xHigh = distance * np.cos(angleHigh * PI / 180);
        curFactorHigh = 1;
        if (row.pos_x_noise_bsm == 0):
            if (angleHigh <= MAX_HEADING_CHANGE):
                curFactorHigh = 1;

            else:
                curFactorHigh = 0;


        else:
            curFactorHigh =calculateCircleSegment(row.pos_x_noise_bsm,
                    row.pos_x_noise_bsm + xHigh) / (PI * row.pos_x_noise_bsm * row.pos_x_noise_bsm);


        oldFactorHigh = 1;
        if (oldRow.pos_x_noise_bsm == 0):
            if (angleHigh <= MAX_HEADING_CHANGE):
                oldFactorHigh = 1;

            else:
                oldFactorHigh = 0;


        else:
            oldFactorHigh = 1 - calculateCircleSegment(oldRow.pos_x_noise_bsm, oldRow.pos_x_noise_bsm - xHigh) / (PI * oldRow.pos_x_noise_bsm * oldRow.pos_x_noise_bsm);

        factor = (curFactorLow + oldFactorLow + curFactorHigh + oldFactorHigh) / 4;

        return factor;

    else:
        return 1; # 1


def calculateHeadingAnglePtr(heading_x_bsm,heading_y_bsm):
    x2 = 1;
    y2 = 0;

    dot = heading_x_bsm * x2 + heading_y_bsm * y2; # dot product between [x1, y1] and [x2, y2]
    det =heading_x_bsm  * y2 - heading_y_bsm * x2;      # determinant
    angle = np.arctan2(det, dot) * 180 / PI; # atan2(y, x) or atan2(sin, cos);

    if (heading_x_bsm  >= 0 and heading_y_bsm  > 0):
        angle = 360 + angle;
    elif (heading_x_bsm < 0 and heading_y_bsm  >= 0):
        angle = 360 + angle;

    return angle;


def calculateHeadingAngle(row):
    x2 = 1;
    y2 = 0;

    dot = row.heading_x_bsm * x2 + row.heading_y_bsm * y2; # dot product between [x1, y1] and [x2, y2]
    det =row.heading_x_bsm  * y2 - row.heading_y_bsm * x2;      # determinant
    angle = np.arctan2(det, dot) * 180 / PI; # atan2(y, x) or atan2(sin, cos);

    if (row.heading_x_bsm  >= 0 and row.heading_y_bsm  > 0):
        angle = 360 + angle;
    elif (row.heading_x_bsm < 0 and row.heading_y_bsm  >= 0):
        angle = 360 + angle;

    return angle;


def positionSpeedConsistancyCheck(row,oldRow):
    MAX_TIME_DELTA = 3.1

    MAX_MGT_RNG_DOWN = 6.2
    MAX_MGT_RNG_UP = 2.1

    MAX_PLAUSIBLE_ACCEL=2.6
    MAX_PLAUSIBLE_DECEL = 4.5

    MAX_PLAUSIBLE_SPEED=15
    MAX_PLAUSIBLE_RANGE=420

    speedDelta = calculateSpeedPtr(row) - calculateSpeedPtr(oldRow)

    curSpeed = calculateSpeedPtr(row)
    oldspeed = calculateSpeedPtr(oldRow)

    time= np.abs(row.rcvTime - oldRow.rcvTime)
    curSpeedConfidence=calculateSpeedConf(row)
    oldSpeedConfidence=calculateSpeedConf(oldRow)

    if (time < MAX_TIME_DELTA):
        distance = calculateDistancePtr(row, oldRow);

        curTest_1 = calculateSpeedPtr(row) + curSpeedConfidence;
        oldTest_1 = calculateSpeedPtr(oldRow) - oldSpeedConfidence;

        curTest_2 = calculateSpeedPtr(row) - curSpeedConfidence;
        oldTest_2 = calculateSpeedPtr(oldRow) + oldSpeedConfidence;

        if (curTest_2 < oldTest_2):
            curTest_2 = (curSpeed + oldspeed) / 2;
            oldTest_2 = (curSpeed + oldspeed) / 2;

        minSpeed = min(curSpeed, oldspeed);

        addon_mgt_range = MAX_MGT_RNG_DOWN + 0.3571 * minSpeed - 0.01694 * minSpeed * minSpeed;
        if (addon_mgt_range < 0):
            addon_mgt_range = 0;


        retDistance_1= [0]*2;
        calculateMaxMinDist(curTest_1, oldTest_1, time,MAX_PLAUSIBLE_ACCEL, MAX_PLAUSIBLE_DECEL, MAX_PLAUSIBLE_SPEED,
            retDistance_1);


        factorMin_1 = 1 - CircleCircleFactor(distance, row.pos_x_noise_bsm, oldRow.pos_x_noise_bsm, retDistance_1[0]);
        factorMax_1 = OneSidedCircleSegmentFactor(distance,row.pos_x_noise_bsm,oldRow.pos_x_noise_bsm,
            retDistance_1[1] + MAX_MGT_RNG_UP)

        retDistance_2 = [0] *2
        calculateMaxMinDist(curTest_2, oldTest_2, time,
            MAX_PLAUSIBLE_ACCEL, MAX_PLAUSIBLE_DECEL, MAX_PLAUSIBLE_SPEED,
            retDistance_2);
        factorMin_2 = 1 - OneSidedCircleSegmentFactor(distance, row.pos_x_noise_bsm,oldRow.pos_x_noise_bsm, retDistance_2[0] - addon_mgt_range);
        factorMax_2 = OneSidedCircleSegmentFactor(distance,
            row.pos_x_noise_bsm,oldRow.pos_x_noise_bsm,
            retDistance_2[1] + MAX_MGT_RNG_UP);

        retDistance_0= [0]*2
        calculateMaxMinDist(curSpeed, oldspeed, time,
            MAX_PLAUSIBLE_ACCEL, MAX_PLAUSIBLE_DECEL, MAX_PLAUSIBLE_SPEED,
            retDistance_0);
        factorMin_0 = 1 - OneSidedCircleSegmentFactor(distance, row.pos_x_noise_bsm, oldRow.pos_x_noise_bsm, retDistance_0[0] - addon_mgt_range);
        factorMax_0 = OneSidedCircleSegmentFactor(distance,
            row.pos_x_noise_bsm,oldRow.pos_x_noise_bsm,
            retDistance_0[1] + MAX_MGT_RNG_UP);


        factorMin = (factorMin_1 + factorMin_0 + factorMin_2) / 3.0;
        factorMax = (factorMax_1 + factorMax_0 + factorMax_2) / 3.0;

        return min(factorMin, factorMax);

    else:
        return INITIAL_TRUST # 1

PI =math.pi

def OneSidedCircleSegmentFactor(d, r1, r2,range):

    if (d < 0):
        return 1;


    if (range > d + r1 + r2):
        return 1;
    else:
        if (range < d - r1 - r2):
            return 0;
        else:
            d1 = 0;
            d2 = 0;
            if (d > 0):
                d1 = (r1 * r1 + d * d - r2 * r2) / (2 * d);
                d2 = (r2 * r2 + d * d - r1 * r1) / (2 * d);
                if ((d1 + r1) < range / 2 and (d2 + r2) > range / 2):
                    d2 = d2 - (range / 2 - (d1 + r1));
                    d1 = d1 + (range / 2 - (d1 + r1));


                if ((d2 + r2) < range / 2 and (d1 + r1) > range / 2):
                    d1 = d1 - (range / 2 - (d2 + r2));
                    d2 = d2 + (range / 2 - (d2 + r2));


            if (r1 <= 0 and r2 <= 0):
                if (range >= d):
                    return 1;
                else:
                    return 0;

            elif (r1 <= 0):
                if (range / 2 >= d1):
                    intD2 = (range / 2) - (d2 - r2);
                    area2 = calculateCircleSegment(r2, intD2);

                    factor = (area2) / (PI * r2 * r2);
                    return factor;
                else:
                    return 0;

            elif (r2 <= 0):
                if (range / 2 >= d2):
                    intD1 = (range / 2) - (d1 - r1);
                    area1 = calculateCircleSegment(r1, intD1);

                    factor = (area1) / (PI * r1 * r1);

                    return factor;
                else:
                    return 0;

            else:

                intD1 = (range / 2) - (d1 - r1);
                intD2 = (range / 2) - (d2 - r2);

                area1 = calculateCircleSegment(r1, intD1);
                area2 = calculateCircleSegment(r2, intD2);

                factor = (area1 + area2) / (PI * r1 * r1 + PI * r2 * r2);

                return factor;




def calculateCircleSegment(radius, intDistance):
    area = 0;

    if (radius <= 0):
        return 0;


    if (intDistance <= 0):
        return 0;


    if (intDistance > 2 * radius):
        return PI * radius * radius;


    if (radius > intDistance):
        area = radius * radius * SafeAcos((radius - intDistance) / radius)- (radius - intDistance)* math.sqrt(
                                2 * radius * intDistance
                                        - intDistance * intDistance);
    else:
        intDistanceTemp = 2 * radius - intDistance;
        area = radius * radius * SafeAcos((radius - intDistanceTemp) / radius)- (radius - intDistanceTemp)* math.sqrt(
                                2 * radius * intDistanceTemp
                                        - intDistanceTemp * intDistanceTemp);
        area = PI * radius * radius - area;


    return area;

def SafeAcos(x):
    if (x < -1.0):
        x = -1.0;
    elif (x > 1.0):
        x = 1.0;
    return np.arccos(x);



def CircleCircleFactor(d, r1, r2,range):

    d1 = 0;
    d2 = 0;
    if (d > 0):
        d1 = (r1 * r1 + d * d - r2 * r2) / (2 * d);
        d2 = (r2 * r2 + d * d - r1 * r1) / (2 * d);

        if ((d1 + r1) < range / 2 and (d2 + r2) > range / 2):
            d2 = d2 - (range / 2 - (d1 + r1));
            d1 = d1 + (range / 2 - (d1 + r1));


        if ((d2 + r2) < range / 2 and (d1 + r1) > range / 2):
            d1 = d1 - (range / 2 - (d2 + r2));
            d2 = d2 + (range / 2 - (d2 + r2));


    if (r1 <= 0 and r2 <= 0):
        if (range >= d):
            return 1;
        else:
            return 0;

    elif (r1 <= 0):
        if (range / 2 >= d1):
            area2 = calculateCircleCircleIntersection(r2, range / 2, d2);
            factor = (area2) / (math.pi * r2 * r2);
            return factor;
        else:
            return 0;

    elif (r2 <= 0) :
        if (range / 2 >= d2):
            area1 = calculateCircleCircleIntersection(r1, range / 2, d1);
            factor = (area1) / (math.pi * r1 * r1);
            return factor;
        else:
            return 0;

    else:
        area1 = calculateCircleCircleIntersection(r1, range / 2, d1);
        area2 = calculateCircleCircleIntersection(r2, range / 2, d2);
        factor = (area1 + area2) / (math.pi * r1 * r1 + math.pi * r2 * r2);
        return factor;



def calculateCircleCircleIntersection(r0,r1,d):

    if (r0 <= 0 or r1 <= 0):
        return 0;


    rr0 = r0 * r0;
    rr1 = r1 * r1;

    # Circles do not overlap
    if (d > r1 + r0):
        return 0;

    # Circle1 is completely inside circle0
    elif (d <= np.abs(r0 - r1) and r0 >= r1):
        # Return area of circle1
        return math.pi * rr1;


# Circle0 is completely inside circle1
    elif (d <= np.abs(r0 - r1) and r0 < r1):
        #Return area of circle0
        return math.pi * rr0;


    else:
        phi = (SafeAcos((rr0 + (d * d) - rr1) / (2 * r0 * d))) * 2;
        theta = (SafeAcos((rr1 + (d * d) - rr0) / (2 * r1 * d))) * 2;
        area1 = 0.5 * theta * rr1 - 0.5 * rr1 * np.sin(theta);
        area2 = 0.5 * phi * rr0 - 0.5 * rr0 * np.sin(phi);

# Return area of intersection
        return area1 + area2;

def calculateMaxMinDist(curSpeed, oldspeed, time,MAX_PLAUSIBLE_ACCEL,MAX_PLAUSIBLE_DECEL,MAX_PLAUSIBLE_SPEED,returnDistance):

    if(curSpeed<0):
        curSpeed = 0;

    if(oldspeed<0):
        oldspeed = 0;


    deltaV = curSpeed - oldspeed;

    T_1 = (deltaV + time * MAX_PLAUSIBLE_DECEL) / (MAX_PLAUSIBLE_ACCEL + MAX_PLAUSIBLE_DECEL);
    T_2 = time - T_1;

    maxSpeed = MAX_PLAUSIBLE_ACCEL * T_1 + oldspeed;
    maxDistance = 0;
    if (maxSpeed > MAX_PLAUSIBLE_SPEED):
        newT_1 = (MAX_PLAUSIBLE_SPEED - oldspeed) / MAX_PLAUSIBLE_ACCEL;
        newT_2 = (MAX_PLAUSIBLE_SPEED - curSpeed)/ MAX_PLAUSIBLE_DECEL;

        maxDistance = oldspeed * newT_1+ 0.5 * MAX_PLAUSIBLE_ACCEL * newT_1 * newT_1+ maxSpeed * newT_2- \
                      0.5 * MAX_PLAUSIBLE_DECEL * newT_2 * newT_2+ MAX_PLAUSIBLE_SPEED * (time - newT_1 - newT_2);
    else:
        maxDistance = oldspeed * T_1 + 0.5 * MAX_PLAUSIBLE_ACCEL * T_1 * T_1 + maxSpeed * T_2 - 0.5 * MAX_PLAUSIBLE_DECEL * T_2 * T_2;


    minSpeed = -MAX_PLAUSIBLE_DECEL * T_2 + oldspeed;
    minDistance = 0;
    if (minSpeed < 0):
        newT_1 = curSpeed / MAX_PLAUSIBLE_ACCEL;
        newT_2 = oldspeed / MAX_PLAUSIBLE_DECEL;

        minDistance = oldspeed * newT_2- 0.5 * MAX_PLAUSIBLE_DECEL * newT_2 * newT_2 + 0.5 * MAX_PLAUSIBLE_ACCEL * newT_1 * newT_1;
    else:
        minDistance = oldspeed * T_2 - 0.5 * MAX_PLAUSIBLE_DECEL * T_2 * T_2 + minSpeed * T_1 + 0.5 * MAX_PLAUSIBLE_ACCEL * T_1 * T_1;


    returnDistance[0] = minDistance;
    returnDistance[1] = maxDistance;



def rangePlausibility(row1,row2):

    MAX_PLAUSIBLE_RANGE=420

    def helper(row1, row2):
        x_2 = (row1.pos_x - row2.pos_x) ** 2
        y_2 = (row1.pos_y - row2.pos_y) ** 2
        return math.sqrt(x_2 + y_2)

    distance = helper(row1,row2)

    factor = CircleCircleFactor(distance,row1.pos_x_noise, row2.pos_x_noise,MAX_PLAUSIBLE_RANGE);

    return factor;


def positionConsistencyCheck(row,oldRow):

    MAX_PLAUSIBLE_SPEED=15

    distance = calculateDistancePtr(row,oldRow)
    timediff= np.abs(row.rcvTime - oldRow.rcvTime)

    if distance<MAX_PLAUSIBLE_SPEED*timediff:
        return 1
    else:
        return 0



def speedConsistencyCheck(row,oldRow):

    MAX_PLAUSIBLE_ACCEL=2.6
    MAX_PLAUSIBLE_DECEL = 4.5


    speedDelta = calculateSpeedPtr(row) - calculateSpeedPtr(oldRow)


    timediff= np.abs(row.rcvTime - oldRow.rcvTime)
    curSpeedConfidence=calculateSpeedConf(row)
    oldSpeedConfidence=calculateSpeedConf(oldRow)

    factor = 1;
    if (speedDelta > 0):
        factor = SegmentSegmentFactor(speedDelta, curSpeedConfidence,
            oldSpeedConfidence, MAX_PLAUSIBLE_ACCEL * timediff)

    else:
        factor = SegmentSegmentFactor(np.abs(speedDelta),
            curSpeedConfidence, oldSpeedConfidence,
            MAX_PLAUSIBLE_DECEL * timediff);


    return factor;



def SegmentSegmentFactor(d, r1,r2,range):

    d1 = 0
    d2 = 0
    if (d > 0) :
        d1 = (r1 * r1 + d * d - r2 * r2) / (2 * d)
        d2 = (r2 * r2 + d * d - r1 * r1) / (2 * d)

        if ((d1 + r1) < range / 2 and (d2 + r2) > range / 2) :
            d2 = d2 - (range / 2 - (d1 + r1))
            d1 = d1 + (range / 2 - (d1 + r1))


        if ((d2 + r2) < range / 2 and (d1 + r1) > range / 2):
            d1 = d1 - (range / 2 - (d2 + r2))
            d2 = d2 + (range / 2 - (d2 + r2))

    overlap1 = 0;
    overlap2 = 0;

    addon = 0;

    if ((d1 - range / 2) < r1):
        if ((d1 - range / 2) > -r1):
            addon = -(d1 - r1)
            overlap1 = range / 2 + addon

        else:
            overlap1 = 2 * r1



    if ((d2 - range / 2) < r2):
        if ((d2 - range / 2) > -r2):
            addon = -(d2 - r2)
            overlap2 = range / 2 + addon

        else:
            overlap2 = 2 * r2


    if (r1 == float(0) and r2 == float(0)):
        if (d > range):
            return 0
        else:
            return 1

    factor = (overlap1 + overlap2 ) / (2 * r1 + 2 * r2)

    return factor



def calculateSpeedPtr(row):

    return math.sqrt(row.spd_x_bsm**2 + row.spd_y_bsm**2)


def calculateSpeedConf(row):
    return math.sqrt(row.spd_x_noise_bsm**2 + row.spd_y_noise_bsm**2)


def calculatePositionConf(row):
    return math.sqrt(row.pos_x_noise_bsm**2 + row.pos_y_noise_bsm**2)

def calculateDistancePtr(row1,row2):
    x_2 = (row1.pos_x_bsm-row2.pos_x_bsm)**2
    y_2 =(row1.pos_y_bsm-row2.pos_y_bsm)**2
    return math.sqrt(x_2+y_2)



def findAndParseAllData(sim_path,num_cases,output_path):
    from functools import partial
    from multiprocessing import Pool

    test_folders = os.listdir(sim_path)

    for i,folder in enumerate(test_folders):
        test_folders[i]=os.path.join(sim_path,folder)


    # Create the pool and start parsing
    func = partial(parseSim, output_path=output_path)
    pool = Pool()
    pool.map(func, test_folders)
    pool.close()
    pool.join()


if __name__ == '__main__':

    sim_path = "raw_logs-veremiExtension/" # raw data path
    num_cases = 2
    output_path ="parsed_logs-veremiExtension/"
    findAndParseAllData(sim_path,num_cases,output_path)
