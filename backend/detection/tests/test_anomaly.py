from backend.detection.ml.anomaly import AnomalyDetector


def test_anomaly_detector():
    detector = AnomalyDetector()

    baseline = [
        [10, 1000],
        [11, 1100],
        [9, 950],
        [10, 1050],
        [12, 1150],
        [11, 1080],
        [10, 1020],
        [9, 980],
    ]

    detector.train(baseline)

    score = detector.score([10, 1000])

    assert 0 <= score <= 100


def test_anomaly_prediction():
    detector = AnomalyDetector()

    baseline = [
        [10, 1000],
        [11, 1100],
        [9, 950],
        [10, 1050],
        [12, 1150],
        [11, 1080],
        [10, 1020],
        [9, 980],
    ]

    detector.train(baseline)

    prediction = detector.predict([10, 1000])

    assert prediction in [-1, 1]