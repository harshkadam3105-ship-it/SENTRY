from backend.detection.features.extractor import FeatureExtractor


def test_feature_extraction():
    extractor = FeatureExtractor()

    event = {
        "features": {
            "packet_count": 100,
            "bytes": 5000,
            "connection_rate": 20,
            "new_process": True,
            "failed_login_count": 6,
            "success_count": 1,
        }
    }

    features = extractor.extract(event)

    assert features["packet_count"] == 100
    assert features["bytes"] == 5000
    assert features["connection_rate"] == 20
    assert features["new_process"] == 1
    assert features["failed_login_count"] == 6


def test_feature_vector():
    extractor = FeatureExtractor()

    event = {
        "features": {
            "packet_count": 10,
            "bytes": 1000,
            "failed_login_count": 2,
        }
    }

    vector = extractor.to_vector(event)

    assert len(vector) == 21
    assert vector[0] == 10
    assert vector[1] == 1000
