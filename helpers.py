import pandas as pd


def convert_json_to_dataframe(json_object):
    """
    Converts a json object into a dataframe.

    :param json_object: json object
    :returns: pandas dataframe
    """
    df = pd.DataFrame.from_dict([json_object], orient='columns')
    return df


def make_prediction(df, model):
    """
    Makes a prediction on df using model.

    :param df: pandas dataframe
    :param model: fitted model with predict_proba method
    """
    return round(model.predict_proba(df)[1], 2)
