import joblib

from modeling.model import FakeModel


def train():
    model = FakeModel()
    joblib.dump(model, 'modeling/model.pkl')


if __name__ == "__main__":
    train()

