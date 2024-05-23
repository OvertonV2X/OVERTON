# OVERTON

This repository contains artifacts for the paper: "OVERTON: Misbehavior Detection and Trust in Vehicular Networks" submitted at the ACM CCS 2024. The artifacts include OVERTON source code and data paths with sample datasets for parsing traffic data and running the framework.

The datasets used in the OVERTON evaluation are provided here: [DRIVE-LINK](https://drive.google.com/drive/folders/1qQ4VvuhZQHSKRFGCB6NnuSjIxne3vDiW?usp=sharing)
## Dependencies

Dependencies:
- Python 3 (tested on Python 3.7)
- Use the package manager [pip](https://pip.pypa.io/en/stable/) to install dependencies for OVERTON:

```bash
pip install -r requirements.txt
```
The [Experiment Data](https://drive.google.com/drive/folders/1qQ4VvuhZQHSKRFGCB6NnuSjIxne3vDiW?usp=sharing) folder includes individual folders for all the experiments presented in the paper.
Each folder contains traffic data logs for the simulations with mentioned attack densities (0.1-0.3) so that the experiments results can be easily reproduced. 

<!---Also, each experiment folder contains the preprocessed traffic logs with extracted features, thus, you could skip the steps (A) and extraction in (B) during evaluation. -->


## Usage

A) veremiSimulationParser.py usage:

execute the command "python3 veremiSimulationParser.py" to parse and preprocess the raw traffic logs collected from VEINS simulations located in the "raw_logs" folder.

Each "logs" folder will generate one parsed log file "!SCENARIO_ID!_parsed.csv" file at the "parsed_logs" folder.

"python veremiExtension_simulationParser.py" is used to parse traffic logs from Veremi-Extension dataset. It implements the plausibility checks and trust calculations which are not native to Veremi-Extension dataset.

B) OVERTON.py usage:


1. Move the parsed logs from previous step to "training_repetitions" and "test_repetitions" folders. First "!SCENARIO_ID!_parsed.csv" is used for training and the second is for test.
2. Run and evaluate OVERTON in parsed traffic scenarios by executing "python OVERTON.py".
3. OVERTON will extract anomaly features from BSM windows, save them to a dedicated folder ("!SCENARIO_ID!_parsed") under train/test repetitions along with vehicular trust logs and use them to train the detection model.
4. The detection model is automatically tested on "test_repetitions", with same procedures applied.



If you want to use previously extracted anomaly features for testing, edit OVERTON.py and set the variable "EXTRACT_FEATURES" to "False", which will skip the extraction step from BSM windows.


 


## License
[MIT](https://choosealicense.com/licenses/mit/)
