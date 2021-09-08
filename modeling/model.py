import numpy as np


class FakeModel:
    def __int__(self):
        pass

    @staticmethod
    def predict_proba(df):
        return np.array([0.1, 0.9])
