import sys
import os
import pandas as pd

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import train_model

os.chdir("testbed")
print("Retraining Model...")
train_model.main()
print("Update complete!")
