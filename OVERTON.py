import json
import os
import numpy as np
from glob import glob
import pandas as pd
from tsfresh import extract_features
from numpy import loadtxt,savetxt
import xgboost as xgb
from sklearn.metrics import auc, accuracy_score, confusion_matrix, mean_squared_error,precision_score,recall_score
from itertools import product
import pickle
from sklearn.metrics import precision_recall_curve
from sklearn.metrics import f1_score
from matplotlib import pyplot
from tsfresh.utilities.dataframe_functions import roll_time_series
import time
import shap

import multiprocessing.pool
from functools import reduce,partial
import gc



pyplot.style.use(['science','ieee','no-latex'])

pyplot.rcParams.update({'font.size': 8})

POOLWORKERS=8
SENDER_ALIAS="sender" # "senderPseudo"

EXTRACT_FEATURES = True
MAX_DISPLAY=15 # for shap
plausibility_modules = [
    "Trust"
]
shap.initjs()

optimal_features = {
                    "maximum": None,
                      "minimum": None,
                     "mean_abs_change": None,
                      "variation_coefficient": None,
                    "fft_coefficient": [{"coeff": k, "attr": a} for a, k in product(["abs", "angle"], range(5))],
                    "sum_of_reoccurring_values": None,
                     "cid_ce": [{"normalize": False}],
                      "mean": None,
                        "autocorrelation": [{"lag": lag} for lag in [1,2]],
                        "percentage_of_reoccurring_values_to_all_values": None,

}



def selectFeatures(extracted_features_path, attacker_filename):
    """takes all csv files in path, creates dataframe and performs a feature selection

    Args:
        extracted_features_path ([type]): [file with the extracted features]
    """


    """Continue regular selectFeatures"""
    path = extracted_features_path  # use your path
    all_files = glob(path + "/*.csv")


    # Early return of selected features
    if False and os.path.exists(path + "/selected_features.csv") and glob(path + "/labels.csv") and glob(
            path + "_attackers.json"):
        print("Early returning of selected features !")
        # os.remove(path + "/selected_features.csv")
        df = pd.read_csv(path + "/selected_features.csv", index_col=0)
        df_labels = loadtxt(path + "/labels.csv", delimiter=',')

        if "labels" in df.columns:
            df = df.drop(['labels'], axis=1)

        return df, df_labels



    li = []

    for filename in all_files:
        if "labels" in filename:  # do not append labels
            continue
        if "selected_features" in filename:
            continue
        if "png" in filename:
            continue

        if not checkIsInOptimals(optimal_features, filename):
            print("NOT OPTIMAL,discarding: "+filename)
            continue

        df = pd.read_csv(filename, index_col=0, header=0)
        li.append(df)

    df = pd.concat(li, axis=1, ignore_index=False)

    if glob(path + "/labels.csv") and glob(path + "_attackers.json"):  # if there exist both attackers and labels
        df_labels = loadtxt(path + "/labels.csv", delimiter=',')

    else:

        if attacker_filename == None:
            attacker_filename = createAttackerRecord(extracted_features_path)

        with open(attacker_filename) as f:
            attacker_dict = json.load(f)
        df_labels = []
        for index, row in df.iterrows():
            current_sender = index.split('_')[0]
            df_labels.append(attacker_dict.get(current_sender, 0))

        df_labels = np.asarray(df_labels, dtype=int)
        # save labels
        label_file_name = path + '/labels.csv'
        savetxt(label_file_name, df_labels, delimiter=',')

    if "labels" in df.columns:
        df = df.drop(['labels'], axis=1)

    if NO_COEFF:
        df.drop(list(df.filter(regex='coeff_0')), axis=1, inplace=True)


    # df = select_features(df, df_labels) # select features
    df.to_csv(path + "/selected_features.csv")

    return df, df_labels


def checkIsInOptimals(optimal_features, filename):
    if not optimal_features:
        return False

    # get the exact feature name from filename
    feature_name = os.path.splitext(os.path.basename(filename))[0] # exact feature name

    for key in optimal_features.keys():

        if key in feature_name:
            return True

    for key in plausibility_modules:
        if key in feature_name:
            return True

    return False


def dfPreProcess(col_name,attacker_filename,filename,output_path):
    # basically does preprocessing done in extract features
    sender_alias = SENDER_ALIAS
    cols_to_be_used = ["rcvTime",sender_alias,"vehicle_ID",col_name]
    df = pd.read_csv(filename,usecols=cols_to_be_used,index_col=False) #,nrows=1000

    # create ID by signal transmission, essentially we have to understand if a signal is from malicious entity
    # Create unique ID column
    df['transmission_ID'] = df[sender_alias].astype(str) + "_" + df['vehicle_ID'].astype(str)

    """can save attacker dicts and use later"""
    with open(attacker_filename) as f:
        attacker_dict = json.load(f)

    # attacker_dict = get_attackers(df)
    #  trim unneccessary columns
    df = df.drop(['sendTime', 'type', 'vehicle_OMNET_ID', 'is_attacker', 'messageID', 'sender', 'senderPseudo','vehicle_ID'], axis=1, errors = 'ignore')
    df["rcvTime"] = df["rcvTime"].astype(int)


    df_labels = []
    for index, row in df.iterrows():
        current_sender = row['transmission_ID'].split('_')[0]
        df_labels.append(attacker_dict.get(current_sender, -1)) # if not present, mark as -1

    df_labels = np.asarray(df_labels, dtype=int)

    # Eliminate -1 labels
    # TODO: Look up to data parsing >why some keys do not exist


    # add labels to dataframe for ease
    df['labels'] = df_labels

    # Plot the data itself
    #from trainWithSelectedFeatures import plotData
    #plotData(df,filename)

    del df['labels']

    ### Perform time rolling
    df['labels'] = df_labels

    # sort df based on time to get ever-increasing time series
    df.sort_values(['transmission_ID','rcvTime'],inplace=True)

    time_window = 10 # 10 steps of windows

    df = roll_time_series(df, max_timeshift=time_window,min_timeshift=1,column_id="transmission_ID", column_sort="rcvTime")#,n_jobs=0

    df['transmission_ID'] =df['id'].apply(lambda x1: x1[0]+"_"+str(x1[1]))
    del df['id']

    df_labels = df['labels']
    del df['labels']



    # Put the transmission Id to first place
    cols = list(df.columns)
    cols = [cols[-1]] + cols[:-1]
    df = df[cols]
    return df,df_labels


def aggregatePlausibilitiesAndSave(col_name,filename,attacker_filename,output_path):
    """
    Aggregate the trust records to be used with the anomaly features
    Args:
        col_name:
        filename:
        attacker_filename:
        output_path:

    Returns:

    """


    feature_file_name = output_path + "/" + col_name + ".csv"  # check if feature is already extracted

    if os.path.isfile(feature_file_name):
        return  # do not extract again

    print("Start Preprocessing of time series")
    start = time.time()
    df, df_labels = dfPreProcess(col_name, attacker_filename, filename, output_path)
    end = time.time()
    print("Processing of: " + filename + " took" + str(end - start) + " seconds")

    features = df.drop_duplicates(subset=['transmission_ID'], keep='last') # hack to get the most recent Trust of window
    del features['rcvTime']

    print("saving features")
    features.fillna(0, inplace=True)  # impute with zero if nan
    features.to_csv(feature_file_name,index=False)

    return


def extractFeaturesAndSave(col_name,filename ,attacker_filename ,output_path):


    features_to_be_extracted = optimal_features
    ##############

    print("Start Preprocessing of time series")
    start = time.time()
    df, df_labels = dfPreProcess(col_name,attacker_filename, filename, output_path)
    end = time.time()
    print("Processing of: " + filename + " took" + str(end - start) + " seconds")



    for key in features_to_be_extracted.keys():
        feature_file_name = output_path + "/" + col_name + "_" + key + ".csv"  # check if feature is already extracted

        if os.path.isfile(feature_file_name):
            continue  # do not extract again

        settings = {key: features_to_be_extracted[key]}
        print("Extracting: " + feature_file_name)
        start = time.time()

        # without stacked dataframe
        extracted_features = extract_features(df, column_id="transmission_ID", column_sort="rcvTime",
                                              default_fc_parameters=settings)#,n_jobs=0
        end=time.time()
        print("Extracting: " + feature_file_name+ " took" + str(end-start) +" seconds")

        extracted_features.fillna(0,inplace=True) # impute with zero if nan
        extracted_features.to_csv(feature_file_name)
        del extracted_features
        #gc.collect()

        pass
    pass


def extractFeaturesFromAllFiles(file_path):
    """
    If needed, extract all the features and save to specific folders
    """

    current_filenames = os.listdir(file_path)

    for training_file in current_filenames:  #  create selected features

        #if not 'veins' in training_file:
        #    continue
        if not 'csv' in training_file:
            continue
        if 'json' in training_file:
            continue

        current_file_path = os.path.join(file_path, training_file)

        basename = os.path.splitext(training_file)[0]
        attacker_filename = os.path.join(file_path,basename+"_attackers.json")

        # If attacker records do not exist, create it

        if not os.path.exists(attacker_filename):
            createAttackerRecord(current_file_path)
            # return  # remove this for full extraction

        output_path =  os.path.join(file_path,basename)
        if not os.path.exists(output_path):
            os.makedirs(output_path)


        # make paralelized version
        col_list = ['pos_x', 'pos_y','spd_x', 'spd_y', 'accel_x', 'accel_y','heading_x', 'heading_y']

        # Create the pool and start extraction
        func = partial(extractFeaturesAndSave,filename=current_file_path ,attacker_filename=attacker_filename ,output_path=output_path)
        pool = MyPool()#MyPool(num_workers=4)
        pool.map(func, col_list)

        considered_modules = plausibility_modules

        func = partial(aggregatePlausibilitiesAndSave, filename=current_file_path, attacker_filename=attacker_filename,
                       output_path=output_path)
        #pool = MyPool(6)
        pool.map(func, considered_modules)
        pool.close()
        pool.join()
        gc.collect()

        print("Everything done")

def trainFromTrainingFiles(train_folder_path):
    # takes all the "selected_features" from the train folder path and trains a single model on all of them


    """First extract all features accordingly"""
    if EXTRACT_FEATURES:
        extractFeaturesFromAllFiles(train_folder_path)
        print("Finished feature extraction")

    training_filenames = os.listdir(train_folder_path)

    li = []
    labels = []
    for training_file in training_filenames:  #  create selected features
        #if not 'veins' in training_file:
        #    continue
        if 'csv' in training_file:
            continue
        if 'json' in training_file:
            continue
        if '.pkl' in training_file:
            continue

        current_file_path = os.path.join(train_folder_path, training_file)

        attacker_filename= os.path.join(train_folder_path,training_file+"_attackers.json")

        print("Selecting features from : "+current_file_path)
        current_features,current_labels = selectFeatures(current_file_path,attacker_filename)  #  no need for attacker filename here, since labels are already inside each feature file
        print(len(current_features.columns))
	
	
        li.append(current_features)
        labels.append(current_labels)
    # exit()
    X_train = pd.concat(li, axis=0, ignore_index=False) #  merge selected features and train on them
    y_train = np.concatenate(labels, axis=0 )
    del li
    print("Start training sequence")
    print(len(X_train.columns))
    # Shuffle the training data and labels for randomizing the attacks
    from sklearn.utils import shuffle
    X_train, y_train = shuffle(X_train, y_train)

    """ Start training the model"""
    if "labels" in X_train.columns:
        X_train = X_train.drop(['labels'], axis=1)


    xgb_model = xgb.XGBClassifier(objective="binary:logistic", random_state=42,n_estimators=400)
    #xgb_model.fit(X_train,y_train,early_stopping_rounds=10, eval_metric="logloss",eval_set=eval_set,verbose=True)
    xgb_model.fit(X_train, y_train, eval_metric="logloss", verbose=True)

    # Save the model to the train data directory for future use
    file_name = train_folder_path + "trained_model.pkl"
    pickle.dump(xgb_model, open(file_name, "wb"))


    return xgb_model


class NoDaemonProcess(multiprocessing.Process):
    # make 'daemon' attribute always return False
    def _get_daemon(self):
        return False
    def _set_daemon(self, value):
        pass
    daemon = property(_get_daemon, _set_daemon)
class MyPool(multiprocessing.pool.Pool):
    Process = NoDaemonProcess


def testModel(train_folder_path,test_folder_path,model=None):
    if model == None:
        model  = pickle.load(open(train_folder_path + "trained_model.pkl", 'rb')) # if you have already trained model, use it


    # extract features if not already extracted
    if EXTRACT_FEATURES:
        extractFeaturesFromAllFiles(test_folder_path)

    print("Started testing!")


    # Load the test repetitions and shuffle
    test_filenames = os.listdir(test_folder_path)

    li = []
    labels = []
    for test_file in test_filenames:  #  create selected features
        #if not 'veins' in test_file:
        #    continue
        if 'csv' in test_file:
            continue
        if 'json' in test_file:
            continue
        if '.png' in test_file:
            continue
        if '.pkl' in test_file:
            continue



        attacker_filename= os.path.join(test_folder_path,test_file+"_attackers.json")
        
	
        current_features_path =os.path.join(test_folder_path, test_file)
        print("Selecting features from : "+current_features_path)
        current_features, current_labels = selectFeatures(current_features_path,
                                                          attacker_filename)  #  no need for attacker filename here, since labels are already inside each feature file

        print(len(current_features.columns))
        current_confusion_matrix = predictWithPretrainedModel(model,current_features_path,current_features,current_labels)
        print(current_confusion_matrix)
        print("Done for now")
        exit()

        li.append(current_features)
        labels.append(current_labels)

    

    X_test = pd.concat(li, axis=0, ignore_index=False)  #  merge selected features a
    y_test = np.concatenate(labels, axis=0)

    #features = borutaFeatureImportance(X=X_test,y=y_test,model=model)

    """ Start training the model"""
    if "labels" in X_test.columns:
        X_test = X_test.drop(['labels'], axis=1)


    # reindex test data to match the model features
    cols_when_model_builds = model.get_booster().feature_names
    X_test = X_test[cols_when_model_builds]


    # make prediction
    y_pred = model.predict(X_test)

    print(confusion_matrix(y_test, y_pred))
    accuracy = accuracy_score(y_test, y_pred)
    print('Accuracy: %.3f' % accuracy)

    precision = precision_score(y_test, y_pred, average='binary')
    print('Precision: %.3f' % precision)
    recall = recall_score(y_test, y_pred, average='binary')
    print('Recall: %.3f' % recall)



    """save the precision recall curve and results"""

    # predict probabilities
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only
    lr_probs = lr_probs[:, 1]
    # predict class values
    lr_precision, lr_recall, _ = precision_recall_curve(y_test, lr_probs)

    # plot the precision-recall curves
    no_skill = len(y_test[y_test == 1]) / len(y_test)
    pyplot.plot([0, 1], [no_skill, no_skill], linestyle='--', label='No Skill')
    pyplot.plot(lr_recall, lr_precision, marker='.', label='Logistic')

    # axis labels
    pyplot.xlabel('Recall')
    pyplot.ylabel('Precision')

    # show the legend
    pyplot.legend()

    # show the grid
    pyplot.grid(True)

    # show the plot
    #pyplot.show()

    # save the plot
    pyplot.savefig(test_folder_path + "_PRcurve.png")
    pyplot.close()


    return model


def predictWithPretrainedModel(model,current_features_path,current_features,current_labels):


    # arrange some variables
    X_test=current_features
    y_test = current_labels

    data_folder_path,directory_name = os.path.split(current_features_path)
    test_folder_path= current_features_path

    print("Current_predicted test file is : " + directory_name)

    # reindex in case column ordering names are differnet
    m_features = model.get_booster().feature_names
    X_test= X_test.reindex(m_features, axis="columns")
    # make prediction
    y_pred = model.predict(X_test)

    print(confusion_matrix(y_test, y_pred))
    accuracy = accuracy_score(y_test, y_pred)
    print('Accuracy: %.3f' % accuracy)

    precision = precision_score(y_test, y_pred, average='binary')
    print('Precision: %.3f' % precision)
    recall = recall_score(y_test, y_pred, average='binary')
    print('Recall: %.3f' % recall)
    
    f_score = f1_score(y_test,y_pred,average='binary')
    print('F1-Score: %.3f' % f_score)
    
    """save the precision recall curve and results"""


    # predict probabilities
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only
    lr_probs = lr_probs[:, 1]
    # predict class values
    lr_precision, lr_recall, _ = precision_recall_curve(y_test, lr_probs)

    # plot the precision-recall curves
    no_skill = len(y_test[y_test == 1]) / len(y_test)
    pyplot.plot([0, 1], [no_skill, no_skill], linestyle='--', label='No Skill')
    pyplot.plot(lr_recall, lr_precision, marker='.', label='Logistic')

    # axis labels
    pyplot.xlabel('Recall')
    pyplot.ylabel('Precision')

    # show the legend
    pyplot.legend()

    # show the grid
    pyplot.grid(True)

    # show the plot
    #pyplot.show()

    # save the plot
    pyplot.savefig(test_folder_path + "_PRcurve.png")
    pyplot.close()

    """
    "Save the misclassified labels"
    false_negatives = [i for i in range(len(y_pred)) if y_pred[i] != y_test[i] and y_pred[i] == 0 and y_test[i] == 1]
    false_positives  = [i for i in range(len(y_pred)) if y_pred[i] != y_test[i] and y_pred[i] == 1 and y_test[i] == 0]
    
    test_ID_col = X_test.index

    false_negative_transmissions = [list(test_ID_col)[i] for i in false_negatives]
    false_positive_transmissions = [list(test_ID_col)[i] for i in false_positives]

    # save false negatives
    df = pd.DataFrame(false_negative_transmissions, columns=["column"])
    df.to_csv(test_folder_path + '_falseNegatives.csv', index=False)
    df = pd.DataFrame(false_positive_transmissions, columns=["column"])
    df.to_csv(test_folder_path + '_falsePositives.csv', index=False)
    print("Saved misclassified labels")
    """

    import shap
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_test)
    pyplot.rcParams.update({'font.size': 8})

    shap.summary_plot(shap_values, X_test,show=False,max_display=MAX_DISPLAY)
    #shap.summary_plot(shap_values[:,my_list], X_test.iloc[:,my_list], show=False, max_display=MAX_DISPLAY)

    pyplot.savefig(test_folder_path+"_ShapleySummarylot.pdf",format='pdf',dpi=1200,bbox_inches = "tight")
    pyplot.close()


    return confusion_matrix(y_test, y_pred)

    # Plotting the misclassified instances, closed for now
    getMisclassifiedInstancesAndPlot(data_folder_path=data_folder_path,directory_name=directory_name,attacker_filename=None)
    return confusion_matrix(y_test, y_pred)


def getMisclassifiedInstancesAndPlot(data_folder_path,directory_name,attacker_filename):
    # misclassified = [i for i in range(len(preds)) if preds[i] != labels[i]]

    path_to_csv = os.path.join(data_folder_path,directory_name)
    df = pd.read_csv(path_to_csv+".csv") # inside the csv directory "one_of_each_attack_cases"

    directory_name= path_to_csv
    if attacker_filename==None:
        attacker_filename=path_to_csv+"_attackers.json"


    false_negatives= pd.read_csv(directory_name+"_falseNegatives.csv")
    false_positives= pd.read_csv(directory_name+ "_falsePositives.csv")


    # preproces the csv
    df['transmission_ID'] = df['sender'].astype(str) + "_" + df['vehicle_ID'].astype(str)

    """can save attacker dicts and use later"""
    with open(attacker_filename) as f:
        attacker_dict = json.load(f)

    df = df.drop(['sendTime', 'type', 'vehicle_OMNET_ID', 'is_attacker', 'messageID', 'sender', 'vehicle_ID'], axis=1,errors='ignore')
    df["rcvTime"] = df["rcvTime"].astype(int)

    df_labels = []
    for index, row in df.iterrows():
        current_sender = row['transmission_ID'].split('_')[0]
        df_labels.append(attacker_dict.get(current_sender, -1))  #  if not present, mark as -1

    df_labels = np.asarray(df_labels, dtype=int)

    # add labels to dataframe for ease
    df['labels'] = df_labels

    # plot the false Negatives and false positives
    false_detections = pd.concat([false_negatives, false_positives])
    #x = df[df['transmission_ID'].isin(false_detections['column'])]  #  take 10 transmissions
    false_detections=false_detections.sample(n=1,random_state=42) # plot 500 of them

    #  Make a directory and start plotting
    directory_name = directory_name + "_false_detected_instances"
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)

    import matplotlib.pyplot as plt

    for index in false_detections['column']:
        old_index = index
        tmp = index.split('_')
        index = tmp[0] + "_" + tmp[1]
        current_data = df[df['transmission_ID'] == index]
        current_label = list(current_data['labels'])[0]  #  get the label of current transmission

        data_columns = current_data.columns[1:8]  # just position and speed daat
        fig, axs = plt.subplots(len(data_columns), sharex=True)

        fig.suptitle("Transmission: " + str(old_index) + " Label: " + str(current_label))
        for i, column in enumerate(data_columns):
            axs[i].plot(current_data['rcvTime'], current_data[column].values)
            pass

        for i, ax in enumerate(axs.flat):
            ax.set(xlabel='Time', ylabel=data_columns[i])

        for ax in axs.flat:
            ax.label_outer()
        # save the figure
        plt.savefig(directory_name + "/false-detected-transmission-" + old_index + ".png")
        plt.close()

    return



def trainAndTestOnDifferentRepetitions(train_folder_path,test_folder_path):
    # put the training repetitions on training folder and test repetitions on test folder ( can be of different attack types)
    # This method will train a model using the repetitions on training folder and test the model on different repetitions on test folder

    train_filenames=os.listdir(train_folder_path)
    test_filenames= os.listdir(test_folder_path)

    print("Training on all attack types :")
    print(train_filenames)
    print("Testing on all attack types :" )
    print(test_filenames)

    model = trainFromTrainingFiles(train_folder_path) # make training from train folder path and return a model

    #model  = pickle.load(open(train_folder_path + "trained_model.pkl", 'rb')) # if you have already trained model, use it
    #model=None
    testModel(train_folder_path,test_folder_path,model=model) # gets model from traning files, tests the model on test repetitions,

def mapPseudonymToID(df):

    pseudonymMap = {}

    for index,row in df.iterrows():
        senderPseudo = int(row['senderPseudo'])
        sender=int(row['sender'])

        if senderPseudo in pseudonymMap:
            if pseudonymMap[senderPseudo] == sender:
                pass
            else:
                # print("Changed Pseudonym of: " + str(senderPseudo))
                pseudonymMap[senderPseudo] = sender
        else:
            pseudonymMap[senderPseudo] = sender

    return pseudonymMap

def get_attackers(df):

    attacker_dict = {}
    # get the attacker signals that are sent by attacker vehicles
    for index,row in df.iterrows():
        if row['is_attacker'] == 1:
            attacker_dict[int(row['vehicle_ID'])] = 1
        else:
            attacker_dict[int(row['vehicle_ID'])] = 0

    if SENDER_ALIAS=="sender":
        return attacker_dict # remove for pseudo
    psedunymMap = mapPseudonymToID(df)

    pseudoAttackers= {k: attacker_dict.get(v,0) for k,v in psedunymMap.items()} # -1

    return pseudoAttackers
    # return attacker_dict

def createAttackerRecord(filename): # extract malicious vehicles from given csv
    #filename = 'test_repetitions/veins_maat.uc1.14505520.180205_173710.csv'
    #filename = filename + ".csv"
    df = pd.read_csv(filename)
    attacker_dict = get_attackers(df)
    json_name = os.path.splitext(filename)[0] + "_attackers.json"
    with open(json_name, 'w') as fp:
        json.dump(attacker_dict, fp)
    return json_name # return the name of dumped file

# Started at 01:20

if __name__ == "__main__":

    # Evaluate on train- test cases seperately
    # REMEMBER TO SET SENDER_ALIAS to SENDERPSEUDO OR SENDER, DEPENDING ON ATTACK TYPE
    # In protocol level veremi extension attacks such as sybil attack, pseudonym change is permitted hence SENDERPSEUDO is used as the unique vehicle alias

    train_folder_path = "training_repetitions/"
    test_folder_path = "test_repetitions/"
    trainAndTestOnDifferentRepetitions(train_folder_path,test_folder_path)
