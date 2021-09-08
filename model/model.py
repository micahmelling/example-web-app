import numpy as np
import joblib


class FakeModel:
    def __int__(self):
        pass

    @staticmethod
    def predict_proba(df):
        return np.array([0.1, 0.9])


def train():
    model = FakeModel()
    joblib.dump(model, 'model/model.pkl')


if __name__ == "__main__":
    train()
